/**
 * Nuclei Template Service
 *
 * Scans the Nuclei templates directory and provides information about
 * available templates, categories, and tags.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as https from 'https';
import { exec } from 'child_process';

// Default template directory (Nuclei's default location in container)
const TEMPLATES_DIR = process.env.NUCLEI_TEMPLATES_DIR || '/root/nuclei-templates';

/**
 * Template category with metadata
 */
export interface TemplateCategory {
  id: string;
  name: string;
  description: string;
  count: number;
  path: string;
}

/**
 * Individual template metadata
 */
export interface TemplateInfo {
  id: string;
  name: string;
  author?: string;
  severity: string;
  description?: string;
  tags: string[];
  reference?: string[];
  cveId?: string;
  cvssScore?: number;
  filePath: string;
  category: string;
}

/**
 * Available tags with counts
 */
export interface TagInfo {
  name: string;
  count: number;
}

/**
 * Template service for scanning and managing Nuclei templates
 */
export class TemplateService {
  private static templatesCache: TemplateInfo[] | null = null;
  private static categoriesCache: TemplateCategory[] | null = null;
  private static tagsCache: TagInfo[] | null = null;
  private static lastCacheTime: number = 0;
  private static CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  /**
   * Check if templates directory exists and is accessible
   */
  static async checkTemplatesDirectory(): Promise<{ exists: boolean; path: string; error?: string }> {
    console.log('[TemplateService] Checking templates directory:', TEMPLATES_DIR);
    try {
      await fs.promises.access(TEMPLATES_DIR, fs.constants.R_OK);
      // Also check if directory has any contents
      const entries = await fs.promises.readdir(TEMPLATES_DIR);
      console.log('[TemplateService] Directory exists with', entries.length, 'entries');
      return { exists: true, path: TEMPLATES_DIR };
    } catch (error: any) {
      console.log('[TemplateService] Directory check failed:', error.message);
      return {
        exists: false,
        path: TEMPLATES_DIR,
        error: error.message,
      };
    }
  }

  /**
   * Get all template categories (top-level directories)
   */
  static async getCategories(): Promise<TemplateCategory[]> {
    // Check cache
    if (this.categoriesCache && Date.now() - this.lastCacheTime < this.CACHE_TTL) {
      return this.categoriesCache;
    }

    const categories: TemplateCategory[] = [];

    try {
      const dirCheck = await this.checkTemplatesDirectory();
      if (!dirCheck.exists) {
        console.log('[TemplateService] Templates directory not found:', TEMPLATES_DIR);
        return this.getDefaultCategories();
      }

      const entries = await fs.promises.readdir(TEMPLATES_DIR, { withFileTypes: true });

      for (const entry of entries) {
        if (entry.isDirectory() && !entry.name.startsWith('.')) {
          const categoryPath = path.join(TEMPLATES_DIR, entry.name);
          const count = await this.countTemplatesInDirectory(categoryPath);

          // Skip empty directories
          if (count === 0) continue;

          categories.push({
            id: entry.name,
            name: this.formatCategoryName(entry.name),
            description: this.getCategoryDescription(entry.name),
            count,
            path: categoryPath,
          });
        }
      }

      // Sort by count descending
      categories.sort((a, b) => b.count - a.count);

      this.categoriesCache = categories;
      this.lastCacheTime = Date.now();

      return categories;
    } catch (error) {
      console.error('[TemplateService] Error reading categories:', error);
      return this.getDefaultCategories();
    }
  }

  /**
   * Get default categories when templates aren't downloaded yet
   * These match the actual top-level directories in nuclei-templates v10+
   */
  private static getDefaultCategories(): TemplateCategory[] {
    return [
      { id: 'http', name: 'HTTP', description: 'HTTP-based vulnerability detection', count: 0, path: '' },
      { id: 'network', name: 'Network', description: 'Network service vulnerability detection', count: 0, path: '' },
      { id: 'dns', name: 'DNS', description: 'DNS-related vulnerability detection', count: 0, path: '' },
      { id: 'ssl', name: 'SSL', description: 'SSL/TLS configuration checks', count: 0, path: '' },
      { id: 'file', name: 'File', description: 'File-based vulnerability detection', count: 0, path: '' },
      { id: 'headless', name: 'Headless', description: 'Browser-based detection templates', count: 0, path: '' },
    ];
  }

  /**
   * Count YAML files in a directory recursively
   */
  private static async countTemplatesInDirectory(dirPath: string): Promise<number> {
    let count = 0;

    try {
      const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        if (entry.isDirectory() && !entry.name.startsWith('.')) {
          count += await this.countTemplatesInDirectory(fullPath);
        } else if (entry.isFile() && (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml'))) {
          count++;
        }
      }
    } catch (error) {
      // Directory might not exist or be inaccessible
    }

    return count;
  }

  /**
   * Format category name for display
   */
  private static formatCategoryName(dirName: string): string {
    return dirName
      .split('-')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  /**
   * Get category description
   */
  private static getCategoryDescription(categoryId: string): string {
    const descriptions: Record<string, string> = {
      'cves': 'Known CVE vulnerabilities from the National Vulnerability Database',
      'vulnerabilities': 'General vulnerability detection templates',
      'exposures': 'Sensitive data exposure detection (files, configs, backups)',
      'misconfiguration': 'Security misconfiguration checks',
      'technologies': 'Technology and version detection',
      'default-logins': 'Default and weak credential detection',
      'takeovers': 'Subdomain takeover detection',
      'file': 'File-based vulnerability detection',
      'network': 'Network service vulnerability detection',
      'dns': 'DNS-related vulnerability detection',
      'ssl': 'SSL/TLS configuration checks',
      'headless': 'Browser-based detection templates',
      'fuzzing': 'Fuzzing templates for vulnerability discovery',
      'workflows': 'Multi-step vulnerability workflows',
      'helpers': 'Helper templates for other detections',
      'iot': 'Internet of Things device vulnerabilities',
      'cloud': 'Cloud service misconfigurations',
    };

    return descriptions[categoryId] || `${this.formatCategoryName(categoryId)} templates`;
  }

  /**
   * Get all available tags across templates
   */
  static async getTags(): Promise<TagInfo[]> {
    // Check cache
    if (this.tagsCache && Date.now() - this.lastCacheTime < this.CACHE_TTL) {
      return this.tagsCache;
    }

    const tagCounts = new Map<string, number>();

    try {
      const templates = await this.getAllTemplates();

      for (const template of templates) {
        for (const tag of template.tags) {
          tagCounts.set(tag, (tagCounts.get(tag) || 0) + 1);
        }
      }

      const tags: TagInfo[] = Array.from(tagCounts.entries())
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);

      this.tagsCache = tags;
      return tags;
    } catch (error) {
      console.error('[TemplateService] Error getting tags:', error);
      return this.getDefaultTags();
    }
  }

  /**
   * Get default tags when templates aren't available
   */
  private static getDefaultTags(): TagInfo[] {
    return [
      { name: 'cve', count: 0 },
      { name: 'rce', count: 0 },
      { name: 'sqli', count: 0 },
      { name: 'xss', count: 0 },
      { name: 'lfi', count: 0 },
      { name: 'ssrf', count: 0 },
      { name: 'auth-bypass', count: 0 },
      { name: 'default-login', count: 0 },
      { name: 'exposure', count: 0 },
      { name: 'misconfiguration', count: 0 },
      { name: 'tech', count: 0 },
      { name: 'panel', count: 0 },
      { name: 'takeover', count: 0 },
      { name: 'token', count: 0 },
      { name: 'unauth', count: 0 },
    ];
  }

  /**
   * Get all templates (with caching)
   */
  static async getAllTemplates(): Promise<TemplateInfo[]> {
    // Check cache
    if (this.templatesCache && Date.now() - this.lastCacheTime < this.CACHE_TTL) {
      return this.templatesCache;
    }

    const templates: TemplateInfo[] = [];

    try {
      const dirCheck = await this.checkTemplatesDirectory();
      if (!dirCheck.exists) {
        return [];
      }

      await this.scanDirectory(TEMPLATES_DIR, '', templates);

      this.templatesCache = templates;
      this.lastCacheTime = Date.now();

      console.log(`[TemplateService] Loaded ${templates.length} templates`);
      return templates;
    } catch (error) {
      console.error('[TemplateService] Error loading templates:', error);
      return [];
    }
  }

  /**
   * Recursively scan directory for templates
   */
  private static async scanDirectory(
    dirPath: string,
    category: string,
    templates: TemplateInfo[]
  ): Promise<void> {
    try {
      const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (entry.name.startsWith('.')) continue;

        const fullPath = path.join(dirPath, entry.name);

        if (entry.isDirectory()) {
          // Use first-level directory as category
          const newCategory = category || entry.name;
          await this.scanDirectory(fullPath, newCategory, templates);
        } else if (entry.isFile() && (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml'))) {
          const template = await this.parseTemplate(fullPath, category);
          if (template) {
            templates.push(template);
          }
        }
      }
    } catch (error) {
      // Directory might not exist or be inaccessible
    }
  }

  /**
   * Parse a single template YAML file
   */
  private static async parseTemplate(filePath: string, category: string): Promise<TemplateInfo | null> {
    try {
      const content = await fs.promises.readFile(filePath, 'utf-8');
      const doc = yaml.load(content) as any;

      if (!doc || !doc.id || !doc.info) {
        return null;
      }

      const info = doc.info;

      return {
        id: doc.id,
        name: info.name || doc.id,
        author: info.author,
        severity: info.severity || 'unknown',
        description: info.description,
        tags: Array.isArray(info.tags) ? info.tags : info.tags?.split(',').map((t: string) => t.trim()) || [],
        reference: Array.isArray(info.reference) ? info.reference : info.reference ? [info.reference] : [],
        cveId: info['cve-id'] || info.classification?.['cve-id']?.[0],
        cvssScore: info['cvss-score'] || info.classification?.['cvss-score'],
        filePath,
        category,
      };
    } catch (error) {
      // Skip files that can't be parsed
      return null;
    }
  }

  /**
   * Search templates by query
   */
  static async searchTemplates(query: string, limit: number = 100): Promise<TemplateInfo[]> {
    const templates = await this.getAllTemplates();
    const queryLower = query.toLowerCase();

    return templates
      .filter(t =>
        t.id.toLowerCase().includes(queryLower) ||
        t.name.toLowerCase().includes(queryLower) ||
        t.description?.toLowerCase().includes(queryLower) ||
        t.tags.some(tag => tag.toLowerCase().includes(queryLower)) ||
        t.cveId?.toLowerCase().includes(queryLower)
      )
      .slice(0, limit);
  }

  /**
   * Get templates by category
   */
  static async getTemplatesByCategory(categoryId: string, limit: number = 100): Promise<TemplateInfo[]> {
    const templates = await this.getAllTemplates();

    return templates
      .filter(t => t.category === categoryId)
      .slice(0, limit);
  }

  /**
   * Get templates by tag
   */
  static async getTemplatesByTag(tag: string, limit: number = 100): Promise<TemplateInfo[]> {
    const templates = await this.getAllTemplates();

    return templates
      .filter(t => t.tags.includes(tag))
      .slice(0, limit);
  }

  /**
   * Get templates by severity
   */
  static async getTemplatesBySeverity(severity: string, limit: number = 100): Promise<TemplateInfo[]> {
    const templates = await this.getAllTemplates();

    return templates
      .filter(t => t.severity === severity)
      .slice(0, limit);
  }

  /**
   * Clear the cache (useful after template updates)
   */
  static clearCache(): void {
    this.templatesCache = null;
    this.categoriesCache = null;
    this.tagsCache = null;
    this.lastCacheTime = 0;
  }

  /**
   * Check if templates directory has actual template files
   */
  private static async hasTemplates(): Promise<boolean> {
    try {
      const count = await this.countTemplatesInDirectory(TEMPLATES_DIR);
      return count > 0;
    } catch {
      return false;
    }
  }

  /**
   * Download/update Nuclei templates
   * For initial download: clones the nuclei-templates repository
   * For updates: uses nuclei -update-templates
   * Custom templates in the 'custom/' directory are preserved
   */
  static async downloadTemplates(): Promise<{
    success: boolean;
    message: string;
    output?: string;
    error?: string;
  }> {
    // Check if templates already exist
    const templatesExist = await this.hasTemplates();
    console.log('[TemplateService] Templates exist:', templatesExist);

    if (!templatesExist) {
      // Initial download: clone the nuclei-templates repository
      return this.cloneTemplates();
    }

    // Update existing templates
    return this.updateTemplates();
  }

  /**
   * Download nuclei-templates tarball for initial download
   * Uses Node.js https to download and tar to extract (no git required)
   */
  private static async cloneTemplates(): Promise<{
    success: boolean;
    message: string;
    output?: string;
    error?: string;
  }> {
    console.log('[TemplateService] Initial download - downloading nuclei-templates to:', TEMPLATES_DIR);

    const tarballUrl = 'https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz';
    const tempTarball = '/tmp/nuclei-templates.tar.gz';
    const tempExtractDir = '/tmp/nuclei-templates-extract';

    try {
      // Step 1: Download the tarball
      console.log('[TemplateService] Step 1: Downloading templates from GitHub...');
      console.log('[TemplateService] URL:', tarballUrl);
      console.log('[TemplateService] Destination:', tempTarball);
      await this.downloadFile(tarballUrl, tempTarball);

      // Verify download
      const stats = await fs.promises.stat(tempTarball);
      console.log('[TemplateService] Step 1 complete: Downloaded', (stats.size / 1024 / 1024).toFixed(2), 'MB');

      // Step 2: Create temp extract directory
      console.log('[TemplateService] Step 2: Creating extract directory:', tempExtractDir);
      await fs.promises.mkdir(tempExtractDir, { recursive: true });
      console.log('[TemplateService] Step 2 complete: Directory created');

      // Step 3: Extract tarball using tar command (available in Alpine)
      console.log('[TemplateService] Step 3: Extracting tarball...');
      await new Promise<void>((resolve, reject) => {
        exec(`tar -xzf ${tempTarball} -C ${tempExtractDir}`, (error, _stdout, stderr) => {
          if (error) {
            console.error('[TemplateService] tar stderr:', stderr);
            reject(new Error(`tar extraction failed: ${stderr || error.message}`));
          } else {
            resolve();
          }
        });
      });
      console.log('[TemplateService] Step 3 complete: Extraction finished');

      // Step 4: Move contents from extracted directory to templates directory
      // The tarball extracts to nuclei-templates-main/
      const extractedDir = path.join(tempExtractDir, 'nuclei-templates-main');
      console.log('[TemplateService] Step 4: Moving templates from', extractedDir, 'to', TEMPLATES_DIR);

      // Check if extracted directory exists
      try {
        await fs.promises.access(extractedDir);
      } catch {
        // List what's in the extract dir to debug
        const extractContents = await fs.promises.readdir(tempExtractDir);
        console.error('[TemplateService] Expected nuclei-templates-main not found. Contents:', extractContents);
        throw new Error(`Extracted directory not found. Contents: ${extractContents.join(', ')}`);
      }

      const entries = await fs.promises.readdir(extractedDir, { withFileTypes: true });
      console.log('[TemplateService] Found', entries.length, 'items to move');

      let movedCount = 0;
      for (const entry of entries) {
        if (entry.name.startsWith('.')) continue; // Skip hidden files
        const src = path.join(extractedDir, entry.name);
        const dest = path.join(TEMPLATES_DIR, entry.name);

        // Preserve custom/ directory if it exists
        if (entry.name === 'custom') {
          try {
            await fs.promises.access(dest);
            console.log('[TemplateService] Preserving existing custom/ directory');
            continue; // Skip if custom/ already exists
          } catch { /* dest doesn't exist, safe to copy */ }
        }

        // Remove destination if exists
        try {
          await fs.promises.rm(dest, { recursive: true, force: true });
        } catch { /* ignore */ }

        // Move the file/directory - use copy+delete for cross-device support
        try {
          await fs.promises.rename(src, dest);
        } catch (renameErr: any) {
          // If rename fails (cross-device), fall back to copy
          if (renameErr.code === 'EXDEV') {
            console.log('[TemplateService] Cross-device move, using copy for:', entry.name);
            await this.copyRecursive(src, dest);
          } else {
            throw renameErr;
          }
        }
        movedCount++;
      }
      console.log('[TemplateService] Step 4 complete: Moved', movedCount, 'items');

      // Step 5: Clean up temp files
      console.log('[TemplateService] Step 5: Cleaning up temp files...');
      await fs.promises.rm(tempTarball, { force: true });
      await fs.promises.rm(tempExtractDir, { recursive: true, force: true });
      console.log('[TemplateService] Step 5 complete: Cleanup done');

      // Clear cache and load templates
      this.clearCache();
      const templates = await this.getAllTemplates();

      console.log('[TemplateService] SUCCESS: Downloaded', templates.length, 'templates');
      return {
        success: true,
        message: `Templates downloaded successfully (${templates.length} templates)`,
        output: 'Downloaded from GitHub tarball and extracted',
      };
    } catch (error: any) {
      console.error('[TemplateService] FAILED at step - Error:', error.message);
      console.error('[TemplateService] Full error:', error);

      // Clean up on error
      try {
        await fs.promises.rm(tempTarball, { force: true });
        await fs.promises.rm(tempExtractDir, { recursive: true, force: true });
      } catch { /* ignore cleanup errors */ }

      return {
        success: false,
        message: `Failed to download templates: ${error.message}`,
        error: error.message,
      };
    }
  }

  /**
   * Download a file from a URL following redirects
   */
  private static async downloadFile(url: string, destPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      console.log('[TemplateService] downloadFile: Starting download...');
      const file = fs.createWriteStream(destPath);
      let downloadTimeout: NodeJS.Timeout;
      let bytesReceived = 0;

      file.on('error', (err) => {
        console.error('[TemplateService] downloadFile: File write error:', err);
        reject(err);
      });

      const makeRequest = (requestUrl: string, redirectCount = 0) => {
        if (redirectCount > 5) {
          console.error('[TemplateService] downloadFile: Too many redirects');
          reject(new Error('Too many redirects'));
          return;
        }

        console.log('[TemplateService] downloadFile: Requesting', requestUrl.substring(0, 80) + '...');
        const request = https.get(requestUrl, (response) => {
          console.log('[TemplateService] downloadFile: Got response status', response.statusCode);

          // Handle redirects
          if (response.statusCode === 301 || response.statusCode === 302) {
            const redirectUrl = response.headers.location;
            if (redirectUrl) {
              console.log('[TemplateService] downloadFile: Following redirect to:', redirectUrl.substring(0, 80) + '...');
              makeRequest(redirectUrl, redirectCount + 1);
              return;
            }
          }

          if (response.statusCode !== 200) {
            console.error('[TemplateService] downloadFile: Bad status code:', response.statusCode);
            reject(new Error(`Download failed with status ${response.statusCode}`));
            return;
          }

          const contentLength = response.headers['content-length'];
          console.log('[TemplateService] downloadFile: Content-Length:', contentLength || 'unknown');

          response.on('data', (chunk) => {
            bytesReceived += chunk.length;
          });

          response.pipe(file);

          file.on('finish', () => {
            clearTimeout(downloadTimeout);
            file.close();
            console.log('[TemplateService] downloadFile: Complete, received', (bytesReceived / 1024 / 1024).toFixed(2), 'MB');
            resolve();
          });
        });

        request.on('error', (error) => {
          console.error('[TemplateService] downloadFile: Request error:', error);
          clearTimeout(downloadTimeout);
          fs.unlink(destPath, () => {}); // Delete incomplete file
          reject(error);
        });
      };

      // 10 minute timeout for download
      downloadTimeout = setTimeout(() => {
        console.error('[TemplateService] downloadFile: Timeout after 10 minutes');
        file.close();
        fs.unlink(destPath, () => {});
        reject(new Error('Download timed out after 10 minutes'));
      }, 10 * 60 * 1000);

      makeRequest(url);
    });
  }

  /**
   * Recursively copy a directory (for cross-device moves)
   */
  private static async copyRecursive(src: string, dest: string): Promise<void> {
    const stat = await fs.promises.stat(src);
    if (stat.isDirectory()) {
      await fs.promises.mkdir(dest, { recursive: true });
      const entries = await fs.promises.readdir(src);
      for (const entry of entries) {
        await this.copyRecursive(path.join(src, entry), path.join(dest, entry));
      }
    } else {
      await fs.promises.copyFile(src, dest);
    }
  }

  /**
   * Update existing templates using nuclei
   */
  private static async updateTemplates(): Promise<{
    success: boolean;
    message: string;
    output?: string;
    error?: string;
  }> {
    const { spawn } = require('child_process');

    return new Promise((resolve) => {
      console.log('[TemplateService] Updating templates in:', TEMPLATES_DIR);

      // Use nuclei -update-templates with -ud to specify the target directory
      const nucleiProcess = spawn('nuclei', ['-update-templates', '-ud', TEMPLATES_DIR], {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      nucleiProcess.stdout?.on('data', (data: Buffer) => {
        const output = data.toString();
        stdout += output;
        console.log('[TemplateService]', output.trim());
      });

      nucleiProcess.stderr?.on('data', (data: Buffer) => {
        const output = data.toString();
        stderr += output;
        // Nuclei outputs info to stderr, not always errors
        console.log('[TemplateService]', output.trim());
      });

      nucleiProcess.on('close', async (code: number | null) => {
        // Clear cache so new templates are picked up
        this.clearCache();

        if (code === 0) {
          // Load templates to get count
          const templates = await this.getAllTemplates();
          console.log('[TemplateService] Template update completed successfully');
          resolve({
            success: true,
            message: `Templates updated successfully (${templates.length} templates)`,
            output: stdout + stderr,
          });
        } else {
          console.error('[TemplateService] Template update failed with code:', code);
          resolve({
            success: false,
            message: `Template update failed with exit code ${code}`,
            error: stderr || stdout,
          });
        }
      });

      nucleiProcess.on('error', (error: Error) => {
        console.error('[TemplateService] Template update error:', error);
        resolve({
          success: false,
          message: 'Failed to start template update',
          error: error.message,
        });
      });

      // Timeout after 5 minutes
      setTimeout(() => {
        nucleiProcess.kill('SIGTERM');
        resolve({
          success: false,
          message: 'Template update timed out after 5 minutes',
        });
      }, 5 * 60 * 1000);
    });
  }

  /**
   * Get summary statistics
   */
  static async getStats(): Promise<{
    totalTemplates: number;
    categories: number;
    tags: number;
    severityCounts: Record<string, number>;
  }> {
    const templates = await this.getAllTemplates();
    const categories = await this.getCategories();
    const tags = await this.getTags();

    const severityCounts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      unknown: 0,
    };

    for (const template of templates) {
      const severity = template.severity.toLowerCase();
      if (severity in severityCounts) {
        severityCounts[severity]++;
      } else {
        severityCounts.unknown++;
      }
    }

    return {
      totalTemplates: templates.length,
      categories: categories.length,
      tags: tags.length,
      severityCounts,
    };
  }
}
