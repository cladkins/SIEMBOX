/**
 * Nuclei Template Service
 *
 * Scans the Nuclei templates directory and provides information about
 * available templates, categories, and tags.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

// Default template directory (Nuclei's default location)
const TEMPLATES_DIR = process.env.NUCLEI_TEMPLATES_DIR || '/root/.local/nuclei-templates';

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
    try {
      await fs.promises.access(TEMPLATES_DIR, fs.constants.R_OK);
      return { exists: true, path: TEMPLATES_DIR };
    } catch (error: any) {
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
   */
  private static getDefaultCategories(): TemplateCategory[] {
    return [
      { id: 'cves', name: 'CVE Templates', description: 'Known CVE vulnerabilities', count: 0, path: '' },
      { id: 'vulnerabilities', name: 'Vulnerabilities', description: 'General vulnerability checks', count: 0, path: '' },
      { id: 'exposures', name: 'Exposures', description: 'Sensitive data exposures', count: 0, path: '' },
      { id: 'misconfiguration', name: 'Misconfigurations', description: 'Security misconfigurations', count: 0, path: '' },
      { id: 'technologies', name: 'Technologies', description: 'Technology detection', count: 0, path: '' },
      { id: 'default-logins', name: 'Default Logins', description: 'Default credential checks', count: 0, path: '' },
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
