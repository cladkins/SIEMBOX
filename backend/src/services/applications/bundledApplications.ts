/**
 * The bundled application signatures: a small starter set, used only when the
 * catalog has no applications/ (a catalog from before application signatures
 * existed), cannot be reached and nothing was read before, and no earlier
 * read is stored in the database. The catalog (cladkins/siembox-catalog,
 * applications/<id>.app.yaml) is the source of truth; appCatalog.ts reads it.
 *
 * Each entry is the catalog file's content, as parsed YAML, so it goes
 * through the same validator as a catalog read. bundledApplications.test.ts
 * checks every entry is identical to its catalog/applications/ mirror file:
 * regenerate this file from the mirror when they differ.
 *
 * Generated from catalog/applications/ (22 signatures).
 */
export const BUNDLED_APPLICATION_DOCS: unknown[] = [
  {
    "schema": "siembox.app/v1",
    "id": "openssh",
    "name": "OpenSSH",
    "vendor": "OpenBSD",
    "category": "remote-access",
    "description": "SSH server (sshd).",
    "website": "https://www.openssh.com",
    "cpe": {
      "vendor": "openbsd",
      "product": "openssh"
    },
    "match": {
      "syslog_program": [
        "sshd",
        "sshd-session"
      ],
      "parser": [
        "ssh-authentication"
      ],
      "service": {
        "banner": [
          "^OpenSSH[_ ](\\d+\\.\\d+(?:p\\d+)?)"
        ]
      },
      "package": [
        "openssh-server",
        "openssh"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "sshd"
      },
      {
        "source": "syslog_program",
        "input": "sshd-session"
      },
      {
        "source": "parser",
        "input": "ssh-authentication"
      },
      {
        "source": "service",
        "input": {
          "name": "ssh",
          "banner": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6"
        },
        "version": "8.9p1"
      },
      {
        "source": "service",
        "input": {
          "name": "ssh"
        },
        "match": false
      },
      {
        "source": "package",
        "input": "openssh-server"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "docker",
    "name": "Docker Engine",
    "vendor": "Docker",
    "category": "container-runtime",
    "description": "Container engine (dockerd) and CLI.",
    "website": "https://www.docker.com",
    "cpe": {
      "vendor": "docker",
      "product": "engine"
    },
    "match": {
      "syslog_program": [
        "dockerd",
        "docker"
      ],
      "service": {
        "names": [
          "docker"
        ]
      },
      "package": [
        "docker-ce",
        "docker.io",
        "docker-engine",
        "moby-engine"
      ],
      "user_agent": [
        "^Docker-Client/(\\d+(?:\\.\\d+)+)"
      ],
      "dns": [
        "docker.io"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "dockerd"
      },
      {
        "source": "service",
        "input": {
          "name": "docker"
        }
      },
      {
        "source": "package",
        "input": "docker-ce"
      },
      {
        "source": "user_agent",
        "input": "Docker-Client/24.0.7 (linux)",
        "version": "24.0.7"
      },
      {
        "source": "dns",
        "input": "registry-1.docker.io"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "nginx",
    "name": "nginx",
    "vendor": "F5",
    "category": "web-server",
    "description": "Web server and reverse proxy.",
    "website": "https://nginx.org",
    "cpe": {
      "vendor": "f5",
      "product": "nginx"
    },
    "match": {
      "syslog_program": [
        "nginx"
      ],
      "parser": [
        "standard-nginx-access",
        "standard-nginx-error",
        "nginx-komodo-error",
        "nginx-komodo-ip-only",
        "nginx-komodo-timestamp-first"
      ],
      "service": {
        "banner": [
          "^nginx(?: (\\d+(?:\\.\\d+)+))?"
        ]
      },
      "container_image": [
        "nginx",
        "nginxinc/nginx-unprivileged",
        "*/nginxinc/nginx-unprivileged",
        "bitnami/nginx",
        "linuxserver/nginx",
        "*/linuxserver/nginx"
      ],
      "package": [
        "nginx",
        "nginx-core",
        "nginx-full",
        "nginx-light",
        "nginx-extras"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "nginx"
      },
      {
        "source": "parser",
        "input": "standard-nginx-access"
      },
      {
        "source": "service",
        "input": {
          "name": "http",
          "banner": "nginx 1.24.0"
        },
        "version": "1.24.0"
      },
      {
        "source": "container_image",
        "input": "nginx:1.25.3-alpine",
        "version": "1.25.3"
      },
      {
        "source": "container_image",
        "input": "docker.io/library/nginx:latest",
        "version": null
      },
      {
        "source": "package",
        "input": "nginx-core"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "traefik",
    "name": "Traefik",
    "vendor": "Traefik Labs",
    "category": "reverse-proxy",
    "description": "Cloud-native reverse proxy and load balancer.",
    "website": "https://traefik.io",
    "cpe": {
      "vendor": "traefik",
      "product": "traefik"
    },
    "match": {
      "syslog_program": [
        "traefik"
      ],
      "parser": [
        "traefik-access"
      ],
      "container_image": [
        "traefik",
        "*/traefik/traefik"
      ],
      "package": [
        "traefik"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "traefik"
      },
      {
        "source": "parser",
        "input": "traefik-access"
      },
      {
        "source": "container_image",
        "input": "traefik:v2.10.7",
        "version": "2.10.7"
      },
      {
        "source": "package",
        "input": "traefik"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "caddy",
    "name": "Caddy",
    "vendor": "Caddy",
    "category": "web-server",
    "description": "Web server with automatic HTTPS.",
    "website": "https://caddyserver.com",
    "cpe": {
      "vendor": "caddyserver",
      "product": "caddy"
    },
    "match": {
      "syslog_program": [
        "caddy"
      ],
      "parser": [
        "caddy-access"
      ],
      "container_image": [
        "caddy",
        "lucaslorentz/caddy-docker-proxy"
      ],
      "package": [
        "caddy"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "caddy"
      },
      {
        "source": "parser",
        "input": "caddy-access"
      },
      {
        "source": "container_image",
        "input": "caddy:2.7.6-alpine",
        "version": "2.7.6"
      },
      {
        "source": "package",
        "input": "caddy"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "plex",
    "name": "Plex Media Server",
    "vendor": "Plex",
    "category": "media-server",
    "description": "Media server for movies, TV and music; clients stream from it locally or through plex.tv.",
    "website": "https://www.plex.tv",
    "cpe": {
      "vendor": "plex",
      "product": "media_server"
    },
    "match": {
      "syslog_program": [
        "plex",
        "plexmediaserver",
        "plex media server"
      ],
      "parser": [
        "plex"
      ],
      "container_image": [
        "plexinc/pms-docker",
        "linuxserver/plex",
        "*/linuxserver/plex",
        "*/hotio/plex"
      ],
      "package": [
        "plexmediaserver"
      ],
      "user_agent": [
        "^PlexMediaServer/(\\d+(?:\\.\\d+)+)"
      ],
      "dns": [
        "plex.tv",
        "plex.direct"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "plex"
      },
      {
        "source": "parser",
        "input": "plex"
      },
      {
        "source": "container_image",
        "input": "lscr.io/linuxserver/plex:1.40.0.7998-c29d4c0c8-ls210",
        "version": "1.40.0.7998"
      },
      {
        "source": "container_image",
        "input": "plexinc/pms-docker:latest",
        "version": null
      },
      {
        "source": "package",
        "input": "plexmediaserver"
      },
      {
        "source": "user_agent",
        "input": "PlexMediaServer/1.40.0.7998-c29d4c0c8",
        "version": "1.40.0.7998"
      },
      {
        "source": "dns",
        "input": "pubsub.plex.tv"
      },
      {
        "source": "dns",
        "input": "192-168-1-20.abcdef0123456789.plex.direct"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "jellyfin",
    "name": "Jellyfin",
    "vendor": "Jellyfin",
    "category": "media-server",
    "description": "Free software media server.",
    "website": "https://jellyfin.org",
    "cpe": {
      "vendor": "jellyfin",
      "product": "jellyfin"
    },
    "match": {
      "syslog_program": [
        "jellyfin"
      ],
      "parser": [
        "jellyfin"
      ],
      "container_image": [
        "jellyfin/jellyfin",
        "*/jellyfin/jellyfin",
        "linuxserver/jellyfin",
        "*/linuxserver/jellyfin"
      ],
      "package": [
        "jellyfin",
        "jellyfin-server"
      ],
      "user_agent": [
        "^Jellyfin-Server/(\\d+(?:\\.\\d+)+)"
      ],
      "dns": [
        "repo.jellyfin.org"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "Jellyfin"
      },
      {
        "source": "parser",
        "input": "jellyfin"
      },
      {
        "source": "container_image",
        "input": "jellyfin/jellyfin:10.8.13",
        "version": "10.8.13"
      },
      {
        "source": "container_image",
        "input": "ghcr.io/jellyfin/jellyfin:10.9.0",
        "version": "10.9.0"
      },
      {
        "source": "package",
        "input": "jellyfin-server"
      },
      {
        "source": "user_agent",
        "input": "Jellyfin-Server/10.8.13",
        "version": "10.8.13"
      },
      {
        "source": "dns",
        "input": "repo.jellyfin.org"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "home-assistant",
    "name": "Home Assistant",
    "vendor": "Home Assistant",
    "category": "home-automation",
    "description": "Home automation platform.",
    "website": "https://www.home-assistant.io",
    "cpe": {
      "vendor": "home-assistant",
      "product": "home-assistant"
    },
    "match": {
      "syslog_program": [
        "homeassistant",
        "home-assistant",
        "home assistant"
      ],
      "parser": [
        "home-assistant"
      ],
      "container_image": [
        "homeassistant/home-assistant",
        "*/home-assistant/home-assistant",
        "linuxserver/homeassistant",
        "*/linuxserver/homeassistant"
      ],
      "user_agent": [
        "^HomeAssistant/(\\d+(?:\\.\\d+)+)"
      ],
      "dns": [
        "home-assistant.io",
        "nabu.casa"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "homeassistant"
      },
      {
        "source": "parser",
        "input": "home-assistant"
      },
      {
        "source": "container_image",
        "input": "ghcr.io/home-assistant/home-assistant:2024.1.5",
        "version": "2024.1.5"
      },
      {
        "source": "container_image",
        "input": "ghcr.io/home-assistant/home-assistant:stable",
        "version": null
      },
      {
        "source": "user_agent",
        "input": "HomeAssistant/2024.1.5 aiohttp/3.9.1 Python/3.11",
        "version": "2024.1.5"
      },
      {
        "source": "dns",
        "input": "version.home-assistant.io"
      },
      {
        "source": "dns",
        "input": "abcdef.ui.nabu.casa"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "pihole",
    "name": "Pi-hole",
    "vendor": "Pi-hole",
    "category": "dns",
    "description": "Network-wide DNS ad blocker.",
    "website": "https://pi-hole.net",
    "cpe": {
      "vendor": "pi-hole",
      "product": "pi-hole"
    },
    "match": {
      "syslog_program": [
        "pihole-ftl",
        "pihole"
      ],
      "parser": [
        "pihole-query",
        "pihole-dns-adblock"
      ],
      "container_image": [
        "pihole/pihole",
        "*/pihole/pihole"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "pihole-FTL"
      },
      {
        "source": "parser",
        "input": "pihole-query"
      },
      {
        "source": "container_image",
        "input": "pihole/pihole:2024.01.0",
        "version": "2024.01.0"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "nextcloud",
    "name": "Nextcloud",
    "vendor": "Nextcloud",
    "category": "file-sharing",
    "description": "File sync and collaboration server, and its desktop and Android clients.",
    "website": "https://nextcloud.com",
    "cpe": {
      "vendor": "nextcloud",
      "product": "nextcloud_server"
    },
    "match": {
      "syslog_program": [
        "nextcloud"
      ],
      "parser": [
        "nextcloud-access"
      ],
      "container_image": [
        "nextcloud",
        "linuxserver/nextcloud",
        "*/linuxserver/nextcloud",
        "nextcloud/all-in-one"
      ],
      "user_agent": [
        "\\bmirall/(\\d+(?:\\.\\d+)+)",
        "\\bNextcloud-android/(\\d+(?:\\.\\d+)+)"
      ],
      "dns": [
        "nextcloud.com"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "nextcloud"
      },
      {
        "source": "parser",
        "input": "nextcloud-access"
      },
      {
        "source": "container_image",
        "input": "nextcloud:28.0.1-apache",
        "version": "28.0.1"
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Linux) mirall/3.11.0 (Nextcloud, ubuntu-6.5.0-14-generic ClientArchitecture: x86_64 OsArchitecture: x86_64)",
        "version": "3.11.0"
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Android) Nextcloud-android/3.27.0",
        "version": "3.27.0"
      },
      {
        "source": "dns",
        "input": "updates.nextcloud.com"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "vaultwarden",
    "name": "Vaultwarden",
    "vendor": "Vaultwarden",
    "category": "password-manager",
    "description": "Bitwarden-compatible password manager server.",
    "website": "https://github.com/dani-garcia/vaultwarden",
    "match": {
      "syslog_program": [
        "vaultwarden"
      ],
      "parser": [
        "vaultwarden-access"
      ],
      "container_image": [
        "vaultwarden/server",
        "*/vaultwarden/server"
      ],
      "package": [
        "vaultwarden"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "vaultwarden"
      },
      {
        "source": "parser",
        "input": "vaultwarden-access"
      },
      {
        "source": "container_image",
        "input": "vaultwarden/server:1.30.1-alpine",
        "version": "1.30.1"
      },
      {
        "source": "package",
        "input": "vaultwarden"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "authelia",
    "name": "Authelia",
    "vendor": "Authelia",
    "category": "auth",
    "description": "Single sign-on and two-factor portal for reverse proxies.",
    "website": "https://www.authelia.com",
    "cpe": {
      "vendor": "authelia",
      "product": "authelia"
    },
    "match": {
      "syslog_program": [
        "authelia"
      ],
      "parser": [
        "authelia-access"
      ],
      "container_image": [
        "authelia/authelia",
        "*/authelia/authelia"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "authelia"
      },
      {
        "source": "parser",
        "input": "authelia-access"
      },
      {
        "source": "container_image",
        "input": "authelia/authelia:4.38.0",
        "version": "4.38.0"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "authentik",
    "name": "authentik",
    "vendor": "Authentik Security",
    "category": "auth",
    "description": "Identity provider (SSO, OAuth, SAML, LDAP).",
    "website": "https://goauthentik.io",
    "cpe": {
      "vendor": "goauthentik",
      "product": "authentik"
    },
    "match": {
      "syslog_program": [
        "authentik server",
        "authentik worker",
        "authentik"
      ],
      "parser": [
        "authentik-asgi-access",
        "authentik-audit",
        "authentik-console"
      ],
      "container_image": [
        "*/goauthentik/server",
        "goauthentik/server",
        "beryju/authentik"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "Authentik Server"
      },
      {
        "source": "parser",
        "input": "authentik-audit"
      },
      {
        "source": "container_image",
        "input": "ghcr.io/goauthentik/server:2024.2.1",
        "version": "2024.2.1"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "postgresql",
    "name": "PostgreSQL",
    "vendor": "PostgreSQL Global Development Group",
    "category": "database",
    "description": "Relational database.",
    "website": "https://www.postgresql.org",
    "cpe": {
      "vendor": "postgresql",
      "product": "postgresql"
    },
    "match": {
      "syslog_program": [
        "postgres",
        "postgresql"
      ],
      "service": {
        "names": [
          "postgresql"
        ]
      },
      "container_image": [
        "postgres",
        "bitnami/postgresql",
        "postgis/postgis",
        "*/cloudnative-pg/postgresql"
      ],
      "package": [
        "postgresql",
        "postgresql-13",
        "postgresql-14",
        "postgresql-15",
        "postgresql-16",
        "postgresql-17"
      ]
    },
    "tests": [
      {
        "source": "syslog_program",
        "input": "postgres"
      },
      {
        "source": "service",
        "input": {
          "name": "postgresql"
        }
      },
      {
        "source": "container_image",
        "input": "postgres:16-alpine",
        "version": "16"
      },
      {
        "source": "container_image",
        "input": "postgres:15.5",
        "version": "15.5"
      },
      {
        "source": "package",
        "input": "postgresql-16"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "ubuntu",
    "name": "Ubuntu",
    "vendor": "Canonical",
    "category": "operating-system",
    "description": "Operating system.",
    "website": "https://ubuntu.com",
    "cpe": {
      "vendor": "canonical",
      "product": "ubuntu_linux"
    },
    "match": {
      "dns": [
        "archive.ubuntu.com",
        "security.ubuntu.com"
      ],
      "os": {
        "family": "linux",
        "pretty_name": "^Ubuntu (\\d+\\.\\d+(?:\\.\\d+)?)"
      }
    },
    "tests": [
      {
        "source": "os",
        "input": {
          "family": "linux",
          "pretty_name": "Ubuntu 22.04.4 LTS"
        },
        "version": "22.04.4"
      },
      {
        "source": "dns",
        "input": "archive.ubuntu.com"
      },
      {
        "source": "dns",
        "input": "us.archive.ubuntu.com"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "debian",
    "name": "Debian",
    "vendor": "Debian",
    "category": "operating-system",
    "description": "Operating system.",
    "website": "https://www.debian.org",
    "cpe": {
      "vendor": "debian",
      "product": "debian_linux"
    },
    "match": {
      "dns": [
        "deb.debian.org",
        "security.debian.org"
      ],
      "os": {
        "family": "linux",
        "pretty_name": "^Debian GNU/Linux (\\d+(?:\\.\\d+)?)"
      }
    },
    "tests": [
      {
        "source": "os",
        "input": {
          "family": "linux",
          "pretty_name": "Debian GNU/Linux 12 (bookworm)"
        },
        "version": "12"
      },
      {
        "source": "dns",
        "input": "deb.debian.org"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "windows",
    "name": "Windows",
    "vendor": "Microsoft",
    "category": "operating-system",
    "description": "Operating system. From a browser user agent the version is the NT version (Windows 10 and 11 both say 10.0).",
    "website": "https://www.microsoft.com/windows",
    "cpe": {
      "vendor": "microsoft",
      "product": "windows"
    },
    "match": {
      "user_agent": [
        "\\(Windows NT (\\d+\\.\\d+)"
      ],
      "dns": [
        "windowsupdate.com"
      ],
      "os": {
        "family": "windows"
      }
    },
    "tests": [
      {
        "source": "os",
        "input": {
          "family": "windows",
          "pretty_name": "windows"
        },
        "version": null
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "version": "10.0"
      },
      {
        "source": "dns",
        "input": "download.windowsupdate.com"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "firefox",
    "name": "Firefox",
    "vendor": "Mozilla",
    "category": "browser",
    "description": "Web browser.",
    "website": "https://www.mozilla.org/firefox/",
    "cpe": {
      "vendor": "mozilla",
      "product": "firefox"
    },
    "match": {
      "user_agent": [
        "\\bFirefox/(\\d+(?:\\.\\d+)*)",
        "\\bFxiOS/(\\d+(?:\\.\\d+)*)"
      ]
    },
    "tests": [
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "version": "121.0"
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/121.0 Mobile/15E148 Safari/605.1.15",
        "version": "121.0"
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "match": false
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "chrome",
    "name": "Chrome",
    "vendor": "Google",
    "category": "browser",
    "description": "Web browser (Chromium-based browsers that do not name themselves look like Chrome).",
    "website": "https://www.google.com/chrome/",
    "cpe": {
      "vendor": "google",
      "product": "chrome"
    },
    "match": {
      "user_agent": [
        "\\bChrome/(\\d+(?:\\.\\d+)*) (?:Mobile )?Safari/",
        "\\bCriOS/(\\d+(?:\\.\\d+)*)"
      ]
    },
    "tests": [
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "version": "120.0.0.0"
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
        "match": false
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        "match": false
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9028 Chrome/120.0.6099.291 Electron/28.2.10 Safari/537.36",
        "match": false
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "match": false
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "edge",
    "name": "Microsoft Edge",
    "vendor": "Microsoft",
    "category": "browser",
    "description": "Web browser.",
    "website": "https://www.microsoft.com/edge",
    "cpe": {
      "vendor": "microsoft",
      "product": "edge_chromium"
    },
    "supersedes": [
      "chrome"
    ],
    "match": {
      "user_agent": [
        "\\bEdg(?:A|iOS)?/(\\d+(?:\\.\\d+)*)"
      ]
    },
    "tests": [
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
        "version": "120.0.2210.91"
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "safari",
    "name": "Safari",
    "vendor": "Apple",
    "category": "browser",
    "description": "Web browser.",
    "website": "https://www.apple.com/safari/",
    "cpe": {
      "vendor": "apple",
      "product": "safari"
    },
    "match": {
      "user_agent": [
        "\\bVersion/(\\d+(?:\\.\\d+)*)(?: Mobile/\\w+)? Safari/"
      ]
    },
    "tests": [
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "version": "17.1"
      },
      {
        "source": "user_agent",
        "input": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "match": false
      }
    ]
  },
  {
    "schema": "siembox.app/v1",
    "id": "curl",
    "name": "curl",
    "vendor": "curl",
    "category": "http-client",
    "description": "Command-line HTTP client.",
    "website": "https://curl.se",
    "cpe": {
      "vendor": "haxx",
      "product": "curl"
    },
    "match": {
      "package": [
        "curl",
        "libcurl4"
      ],
      "user_agent": [
        "^curl/(\\d+(?:\\.\\d+)*)"
      ]
    },
    "tests": [
      {
        "source": "user_agent",
        "input": "curl/7.81.0",
        "version": "7.81.0"
      },
      {
        "source": "user_agent",
        "input": "curl/8.0",
        "version": "8.0"
      },
      {
        "source": "package",
        "input": "curl"
      }
    ]
  },
];
