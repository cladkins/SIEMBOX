/**
 * The bundled suggested scans: a small starter set, used only when the catalog
 * has no scans/ (a catalog from before suggested scans existed) or cannot be
 * reached and nothing was read before. The catalog (cladkins/siembox-catalog,
 * scans/<id>.scan.yaml) is the source of truth; scanCatalog.ts reads it.
 *
 * Each entry is the catalog file's content, as parsed YAML, so it goes through
 * the same validator as a catalog read. scanCatalog.test.ts checks every entry
 * is identical to its catalog/scans/ mirror file: regenerate this file from
 * the mirror when they differ (parse each listed file with js-yaml and write
 * the array as JSON).
 *
 * Generated from catalog/scans/ (14 of the mirror's suggestions).
 */
export const BUNDLED_SCAN_DOCS: unknown[] = [
  {
    "schema": "siembox.scan/v1",
    "id": "asset-host-discovery-daily",
    "name": "Daily host discovery (ping sweep)",
    "kind": "asset",
    "category": "inventory",
    "tags": [
      "nmap",
      "ping",
      "inventory"
    ],
    "description": "Sweeps your subnets with an Nmap ping scan (-sn, no ports) once a night and records every host that answers in Asset Inventory.",
    "why": "The cheapest way to keep the asset list current. Start here: new devices, re-addressed ones and hosts that went quiet show up the next morning, and every other scan works from a known set of hosts.",
    "intrusive": false,
    "load": "light",
    "schedule": {
      "frequency": "daily",
      "time": "01:15"
    },
    "options": {
      "scanType": "ping"
    },
    "inputs": [
      {
        "field": "targets",
        "label": "Subnets to sweep",
        "hint": "Your own LAN subnets in CIDR form, one per line."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "Pick a log shipper on that network when SIEMBox itself cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "asset-port-scan-weekly",
    "name": "Weekly open-port scan (top 1000 TCP)",
    "kind": "asset",
    "category": "services",
    "tags": [
      "nmap",
      "ports"
    ],
    "description": "An Nmap TCP connect scan of ports 1-1000 on every host in your subnets, once a week, recording open ports per asset.",
    "why": "Shows what each host exposes and catches a service that was opened without anyone noticing (an admin panel, a database port). Weekly on a Sunday night keeps the load off working hours.",
    "intrusive": false,
    "load": "moderate",
    "schedule": {
      "frequency": "weekly",
      "days": [
        0
      ],
      "time": "02:00"
    },
    "options": {
      "scanType": "port"
    },
    "inputs": [
      {
        "field": "targets",
        "label": "Subnets or hosts",
        "hint": "The networks or hosts to scan, as IPs or CIDRs."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "asset-service-versions-weekly",
    "name": "Weekly service and version detection",
    "kind": "asset",
    "category": "services",
    "tags": [
      "nmap",
      "services",
      "versions"
    ],
    "description": "An Nmap version scan (-sV, ports 1-1000) once a week: open ports with the product and version of the service behind each one.",
    "why": "Versions are what vulnerability linking and Application Monitoring work from, so this turns \"port 443 is open\" into \"nginx 1.24 is running\". It takes longer than a plain port scan; run it on a quiet night.",
    "intrusive": false,
    "load": "moderate",
    "schedule": {
      "frequency": "weekly",
      "days": [
        6
      ],
      "time": "03:00"
    },
    "options": {
      "scanType": "service"
    },
    "inputs": [
      {
        "field": "targets",
        "label": "Subnets or hosts",
        "hint": "The networks or hosts to fingerprint, as IPs or CIDRs."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "vuln-critical-high-cves-weekly",
    "name": "Weekly critical and high CVE scan",
    "kind": "vulnerability",
    "category": "cves",
    "tags": [
      "nuclei",
      "cve"
    ],
    "description": "Runs the Nuclei CVE templates rated critical or high against a host or range once a week, skipping templates tagged intrusive, dos or fuzz.",
    "why": "The baseline vulnerability scan: known, exploitable flaws in what you run, without the noise of hundreds of informational findings. Pair it with the weekly service scan so findings link to the right assets.",
    "intrusive": false,
    "load": "moderate",
    "schedule": {
      "frequency": "weekly",
      "days": [
        0
      ],
      "time": "03:00"
    },
    "options": {
      "templateSelection": {
        "cves": true,
        "severities": [
          "critical",
          "high"
        ],
        "excludeTags": [
          "intrusive",
          "dos",
          "fuzz"
        ]
      },
      "rateLimit": 100
    },
    "inputs": [
      {
        "field": "target",
        "label": "Host or range",
        "hint": "One host, IP or CIDR range you own or are authorized to scan."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "vuln-known-exploited-daily",
    "name": "Daily known-exploited vulnerability check (KEV)",
    "kind": "vulnerability",
    "category": "cves",
    "tags": [
      "nuclei",
      "kev",
      "cve"
    ],
    "description": "Every night, the Nuclei templates tagged kev: vulnerabilities on CISA's Known Exploited Vulnerabilities list, the ones attackers use in the wild.",
    "why": "A small, high-signal template set that is cheap enough to run daily, so a newly listed exploited flaw is caught within a day of the templates being updated. Point it at internet-facing hosts first.",
    "intrusive": false,
    "load": "light",
    "schedule": {
      "frequency": "daily",
      "time": "04:00"
    },
    "options": {
      "templateSelection": {
        "tags": [
          "kev"
        ],
        "excludeTags": [
          "intrusive",
          "dos",
          "fuzz"
        ]
      },
      "rateLimit": 100
    },
    "inputs": [
      {
        "field": "target",
        "label": "Host or range",
        "hint": "Start with what is exposed to the internet (a reverse proxy, a VPN gateway)."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "vuln-exposed-panels-weekly",
    "name": "Weekly exposed admin panel check",
    "kind": "vulnerability",
    "category": "exposure",
    "tags": [
      "nuclei",
      "panel",
      "exposure"
    ],
    "description": "Finds login and admin panels (routers, NAS boxes, hypervisors, CI servers, databases' web consoles) with the Nuclei panel templates, once a week.",
    "why": "An admin panel reachable from the wrong network is one of the most common ways in. This only detects that a panel answers; it never tries to log in.",
    "intrusive": false,
    "load": "light",
    "schedule": {
      "frequency": "weekly",
      "days": [
        1
      ],
      "time": "05:00"
    },
    "options": {
      "templateSelection": {
        "tags": [
          "panel"
        ],
        "excludeTags": [
          "intrusive",
          "dos",
          "fuzz"
        ]
      },
      "rateLimit": 100
    },
    "inputs": [
      {
        "field": "target",
        "label": "Host or range",
        "hint": "A host or CIDR range, ideally as seen from the less trusted side of your firewall."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "vuln-tls-weekly",
    "name": "Weekly TLS certificate and configuration check",
    "kind": "vulnerability",
    "category": "tls",
    "tags": [
      "nuclei",
      "tls",
      "certificates"
    ],
    "description": "The Nuclei ssl/ templates once a week: expired, soon-to-expire, self-signed and mismatched certificates, deprecated protocol versions and weak ciphers.",
    "why": "Catches the certificate that is about to expire before users see the browser warning, and the old appliance still offering TLS 1.0.",
    "intrusive": false,
    "load": "light",
    "schedule": {
      "frequency": "weekly",
      "days": [
        6
      ],
      "time": "04:30"
    },
    "options": {
      "templateSelection": {
        "templates": [
          "ssl/"
        ],
        "excludeTags": [
          "intrusive",
          "dos",
          "fuzz"
        ]
      },
      "rateLimit": 50
    },
    "inputs": [
      {
        "field": "target",
        "label": "Host or range",
        "hint": "The hosts that serve TLS (web servers, mail, VPN), as a host, IP or CIDR."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "container-all-images-nightly",
    "name": "Nightly scan of every container image",
    "kind": "container",
    "category": "containers",
    "tags": [
      "trivy",
      "images"
    ],
    "description": "Every night, a Trivy scan of every image SIEMBox can see: the images on the SIEMBox host (Docker socket) and on each log shipper's host. Images started since the schedule was added are picked up automatically.",
    "why": "New CVEs are published daily against packages already inside your images, so an image that was clean last month may not be now. Nothing to fill in: just enable it.",
    "intrusive": false,
    "load": "moderate",
    "schedule": {
      "frequency": "daily",
      "time": "05:00"
    },
    "options": {
      "all_images": true
    },
    "inputs": []
  },
  {
    "schema": "siembox.scan/v1",
    "id": "container-single-image-daily",
    "name": "Daily scan of one important image",
    "kind": "container",
    "category": "containers",
    "tags": [
      "trivy",
      "image"
    ],
    "description": "A daily Trivy scan of one image you name, pulled fresh on each run.",
    "why": "For the image that matters most (the one facing the internet, or the one you build and publish yourself), including an image not running on any host SIEMBox can see.",
    "intrusive": false,
    "load": "light",
    "schedule": {
      "frequency": "daily",
      "time": "06:15"
    },
    "options": {},
    "inputs": [
      {
        "field": "image_ref",
        "label": "Image",
        "hint": "An image reference as you would pass it to docker pull (repository and tag)."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "logdisc-passive-daily",
    "name": "Daily passive log source discovery",
    "kind": "log_discovery",
    "category": "log-sources",
    "tags": [
      "log-discovery",
      "passive"
    ],
    "description": "A passive Log Discovery run every day: reads what the network already announces (the ARP table, mDNS, SSDP, DHCP leases, LLDP) without sending a packet to any host, and ranks the devices that could be sending logs.",
    "why": "Finds log sources you have not onboarded yet without touching any host. Leave the CIDRs empty to use the scope saved on the Log Discovery page.",
    "intrusive": false,
    "load": "light",
    "schedule": {
      "frequency": "daily",
      "time": "00:45"
    },
    "options": {
      "mode": "passive"
    },
    "inputs": [
      {
        "field": "cidrs",
        "label": "Subnets (optional)",
        "hint": "Leave empty to use the Log Discovery scope; otherwise your LAN subnets in CIDR form."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "logdisc-full-monthly",
    "name": "Monthly full log source discovery",
    "kind": "log_discovery",
    "category": "log-sources",
    "tags": [
      "log-discovery",
      "full"
    ],
    "description": "A full Log Discovery run (passive, then active) on the 2nd of each month, refreshing the ranked list of log sources to onboard.",
    "why": "A monthly review of logging coverage: everything passive and active discovery can find in one run, on a quiet night.",
    "intrusive": false,
    "load": "moderate",
    "schedule": {
      "frequency": "monthly",
      "day_of_month": 2,
      "time": "02:45"
    },
    "options": {
      "mode": "full"
    },
    "inputs": [
      {
        "field": "cidrs",
        "label": "Subnets (optional)",
        "hint": "Leave empty to use the Log Discovery scope; otherwise your LAN subnets in CIDR form."
      },
      {
        "field": "shipper",
        "label": "Run from",
        "hint": "A log shipper on that network, if SIEMBox cannot reach it."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "endpoint-workstations-business-hours",
    "name": "Workstations — business hours, light",
    "kind": "endpoint_policy",
    "category": "endpoints",
    "tags": [
      "endpoint",
      "workstations"
    ],
    "description": "Desktops that are on during the working day: every scan runs between 09:00 and 17:00 on weekdays and stays light (vulnerabilities and YARA weekly, packages daily, system inventory hourly).",
    "why": "Workstations are often off at night, so night-time scans never run. This keeps scans inside working hours and spreads the heavier ones across the week so no single day is slow for the user.",
    "intrusive": false,
    "load": "light",
    "options": {
      "scans": {
        "vuln": {
          "enabled": true,
          "schedule": {
            "frequency": "weekly",
            "days": [
              3
            ],
            "time": "12:30"
          },
          "window": {
            "start": "09:00",
            "end": "17:00"
          }
        },
        "yara": {
          "enabled": true,
          "schedule": {
            "frequency": "weekly",
            "days": [
              5
            ],
            "time": "12:00"
          },
          "window": {
            "start": "09:00",
            "end": "17:00"
          }
        },
        "packages": {
          "enabled": true,
          "schedule": {
            "frequency": "weekly",
            "days": [
              1,
              2,
              3,
              4,
              5
            ],
            "time": "10:15"
          },
          "window": {
            "start": "09:00",
            "end": "17:00"
          }
        },
        "inventory": {
          "enabled": true,
          "interval_minutes": 60,
          "window": {
            "start": "09:00",
            "end": "17:00"
          }
        }
      }
    },
    "inputs": [
      {
        "field": "endpoints",
        "label": "Endpoints",
        "hint": "Select the workstations on the Endpoints page, then Assign policy."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "endpoint-servers-nightly-full",
    "name": "Servers — nightly full",
    "kind": "endpoint_policy",
    "category": "endpoints",
    "tags": [
      "endpoint",
      "servers"
    ],
    "description": "Always-on servers: vulnerabilities, a full YARA pass and packages every night between midnight and 06:00, system inventory hourly.",
    "why": "Servers are up at night and quiet then, so they can afford a full check every day; findings are fresh each morning and the load stays out of working hours.",
    "intrusive": false,
    "load": "moderate",
    "options": {
      "scans": {
        "vuln": {
          "enabled": true,
          "schedule": {
            "frequency": "daily",
            "time": "02:00"
          },
          "window": {
            "start": "00:00",
            "end": "06:00"
          }
        },
        "yara": {
          "enabled": true,
          "schedule": {
            "frequency": "daily",
            "time": "03:00"
          },
          "window": {
            "start": "00:00",
            "end": "06:00"
          }
        },
        "packages": {
          "enabled": true,
          "schedule": {
            "frequency": "daily",
            "time": "01:00"
          },
          "window": {
            "start": "00:00",
            "end": "06:00"
          }
        },
        "inventory": {
          "enabled": true,
          "interval_minutes": 60
        }
      }
    },
    "inputs": [
      {
        "field": "endpoints",
        "label": "Endpoints",
        "hint": "Select the servers on the Endpoints page, then Assign policy."
      }
    ]
  },
  {
    "schema": "siembox.scan/v1",
    "id": "endpoint-laptops-weekly",
    "name": "Laptops — weekly",
    "kind": "endpoint_policy",
    "category": "endpoints",
    "tags": [
      "endpoint",
      "laptops"
    ],
    "description": "Laptops that come and go: vulnerabilities, YARA and packages once a week in the daytime, system inventory every four hours. A scan missed while the laptop was away runs once when it reconnects (inside the 08:00-20:00 window).",
    "why": "Laptops run on battery and are often asleep or off-site, so frequent or night-time scans either never run or drain the battery. Weekly daytime scans keep them covered without users noticing.",
    "intrusive": false,
    "load": "light",
    "options": {
      "scans": {
        "vuln": {
          "enabled": true,
          "schedule": {
            "frequency": "weekly",
            "days": [
              1
            ],
            "time": "11:00"
          },
          "window": {
            "start": "08:00",
            "end": "20:00"
          }
        },
        "yara": {
          "enabled": true,
          "schedule": {
            "frequency": "weekly",
            "days": [
              3
            ],
            "time": "13:00"
          },
          "window": {
            "start": "08:00",
            "end": "20:00"
          }
        },
        "packages": {
          "enabled": true,
          "schedule": {
            "frequency": "weekly",
            "days": [
              1
            ],
            "time": "10:00"
          },
          "window": {
            "start": "08:00",
            "end": "20:00"
          }
        },
        "inventory": {
          "enabled": true,
          "interval_minutes": 240
        }
      }
    },
    "inputs": [
      {
        "field": "endpoints",
        "label": "Endpoints",
        "hint": "Select the laptops on the Endpoints page, then Assign policy."
      }
    ]
  }
];
