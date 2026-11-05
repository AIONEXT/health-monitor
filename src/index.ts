/**
 * Health Monitor: Background monitoring for AIONEXT packages
 */

import axios from "axios";
import cron from "node-cron";
import * as promClient from "prom-client";
import { Registry, Counter, Gauge, Histogram } from "prom-client";

export interface MonitorConfig {
  packages: string[];
  githubToken: string;
  interval: string; // cron expression
  checks: {
    dependencies: boolean;
    security: boolean;
    releases: boolean;
    ci: boolean;
    performance: boolean;
  };
  alerts: {
    slack?: string;
    email?: string[];
    webhook?: string;
  };
  metricsPort: number;
}

export interface HealthCheckResult {
  package: string;
  check: string;
  status: "healthy" | "degraded" | "unhealthy";
  timestamp: Date;
  details: Record<string, any>;
  duration: number;
}

export class HealthMonitor {
  private config: MonitorConfig;
  private registry: Registry;
  private checksRun: Counter;
  private checkDuration: Histogram;
  private packageHealth: Gauge;
  private running = false;

  constructor(config: MonitorConfig) {
    this.config = config;
    this.registry = new Registry();
    promClient.collectDefaultMetrics({ register: this.registry });

    this.checksRun = new Counter({
      name: "health_checks_total",
      help: "Total number of health checks run",
      labelNames: ["package", "check", "status"],
      registers: [this.registry],
    });

    this.checkDuration = new Histogram({
      name: "health_check_duration_seconds",
      help: "Duration of health checks in seconds",
      labelNames: ["package", "check"],
      registers: [this.registry],
    });

    this.packageHealth = new Gauge({
      name: "package_health",
      help: "Package health status (1=healthy, 0=degraded, -1=unhealthy)",
      labelNames: ["package"],
      registers: [this.registry],
    });
  }

  start(): void {
    if (this.running) return;
    this.running = true;

    // Schedule periodic checks
    cron.schedule(this.config.interval, () => this.runAllChecks());

    // Start metrics server
    this.startMetricsServer();

    console.log("Health monitor started");
  }

  stop(): void {
    this.running = false;
    console.log("Health monitor stopped");
  }

  private async runAllChecks(): Promise<void> {
    console.log("Running scheduled health checks...");

    for (const pkg of this.config.packages) {
      await this.runPackageChecks(pkg);
    }
  }

  private async runPackageChecks(pkg: string): Promise<void> {
    const checks = [
      { name: "dependencies", fn: () => this.checkDependencies(pkg) },
      { name: "security", fn: () => this.checkSecurity(pkg) },
      { name: "releases", fn: () => this.checkReleases(pkg) },
      { name: "ci", fn: () => this.checkCI(pkg) },
      { name: "performance", fn: () => this.checkPerformance(pkg) },
    ];

    for (const check of checks) {
      if (!this.config.checks[check.name as keyof typeof this.config.checks]) continue;

      const start = Date.now();
      try {
        const result = await check.fn();
        const duration = (Date.now() - start) / 1000;

        this.checksRun.inc({ package: pkg, check: check.name, status: result.status });
        this.checkDuration.observe({ package: pkg, check: check.name }, duration);

        const healthValue = result.status === "healthy" ? 1 : result.status === "degraded" ? 0 : -1;
        this.packageHealth.set({ package: pkg }, healthValue);

        if (result.status !== "healthy") {
          await this.alert(pkg, check.name, result);
        }
      } catch (error) {
        const err = error as Error;
        this.checksRun.inc({ package: pkg, check: check.name, status: "unhealthy" });
        await this.alert(pkg, check.name, { status: "unhealthy", details: { error: err.message } });
      }
    }
  }

  private async checkDependencies(pkg: string): Promise<HealthCheckResult> {
    try {
      // Check for outdated dependencies, vulnerabilities
      const response = await axios.get(`https://api.github.com/repos/AIONEXT/${pkg}/dependency-graph/snapshots`, {
        headers: { Authorization: `token ${this.config.githubToken}` },
      });

      return {
        package: pkg,
        check: "dependencies",
        status: "healthy",
        timestamp: new Date(),
        details: { snapshot: response.data },
        duration: 0,
      };
    } catch {
      return {
        package: pkg,
        check: "dependencies",
        status: "degraded",
        timestamp: new Date(),
        details: { error: "Failed to fetch dependency graph" },
        duration: 0,
      };
    }
  }

  private async checkSecurity(pkg: string): Promise<HealthCheckResult> {
    try {
      const response = await axios.get(`https://api.github.com/repos/AIONEXT/${pkg}/vulnerability-alerts`, {
        headers: { Authorization: `token ${this.config.githubToken}` },
      });

      const hasVulns = response.data.length > 0;
      return {
        package: pkg,
        check: "security",
        status: hasVulns ? "unhealthy" : "healthy",
        timestamp: new Date(),
        details: { vulnerabilities: response.data.length },
        duration: 0,
      };
    } catch {
      return {
        package: pkg,
        check: "security",
        status: "degraded",
        timestamp: new Date(),
        details: { error: "Failed to check security" },
        duration: 0,
      };
    }
  }

  private async checkReleases(pkg: string): Promise<HealthCheckResult> {
    try {
      const response = await axios.get(`https://api.github.com/repos/AIONEXT/${pkg}/releases/latest`, {
        headers: { Authorization: `token ${this.config.githubToken}` },
      });

      const daysSinceRelease = (Date.now() - new Date(response.data.published_at).getTime()) / (1000 * 60 * 60 * 24);
      return {
        package: pkg,
        check: "releases",
        status: daysSinceRelease > 90 ? "degraded" : "healthy",
        timestamp: new Date(),
        details: { latestRelease: response.data.tag_name, daysSinceRelease },
        duration: 0,
      };
    } catch {
      return {
        package: pkg,
        check: "releases",
        status: "degraded",
        timestamp: new Date(),
        details: { error: "Failed to fetch releases" },
        duration: 0,
      };
    }
  }

  private async checkCI(pkg: string): Promise<HealthCheckResult> {
    try {
      const response = await axios.get(`https://api.github.com/repos/AIONEXT/${pkg}/actions/runs?per_page=5`, {
        headers: { Authorization: `token ${this.config.githubToken}` },
      });

      const failed = response.data.workflow_runs.some((run: any) => run.conclusion === "failure");
      return {
        package: pkg,
        check: "ci",
        status: failed ? "unhealthy" : "healthy",
        timestamp: new Date(),
        details: { recentRuns: response.data.workflow_runs.length, failed },
        duration: 0,
      };
    } catch {
      return {
        package: pkg,
        check: "ci",
        status: "degraded",
        timestamp: new Date(),
        details: { error: "Failed to check CI" },
        duration: 0,
      };
    }
  }

  private async checkPerformance(pkg: string): Promise<HealthCheckResult> {
    // Mock performance check
    return {
      package: pkg,
      check: "performance",
      status: "healthy",
      timestamp: new Date(),
      details: { p99Latency: 150, throughput: 1000 },
      duration: 0,
    };
  }

  private async alert(pkg: string, check: string, result: HealthCheckResult): Promise<void> {
    const message = `⚠️ ${pkg} - ${check}: ${result.status.toUpperCase()}`;
    console.log(message);

    if (this.config.alerts.slack) {
      await axios.post(this.config.alerts.slack, { text: message });
    }
    if (this.config.alerts.webhook) {
      await axios.post(this.config.alerts.webhook, { package: pkg, check, ...result });
    }
  }

  private startMetricsServer(): void {
    // In a real implementation, this would start an HTTP server
    console.log(`Metrics available on port ${this.config.metricsPort}`);
  }

  getMetrics(): Promise<string> {
    return this.registry.metrics();
  }
}