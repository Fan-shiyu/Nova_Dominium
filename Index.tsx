import { useState } from "react";
import { CloudUpload, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { toast } from "sonner";
import { FileUpload } from "@/components/FileUpload";
import { DomainTable } from "@/components/DomainTable";
import { ResultsTable } from "@/components/ResultsTable";
import { SummaryCard } from "@/components/SummaryCard";

export interface Domain {
  domain_name: string;
}

export interface WhoisResult {
  domain_name: string;
  registrant_name: string;
  registrant_org: string;
  registrar: string;
  registry: string;
  creation_date: string;
  expiry_date: string;
  nameservers: string;
  data_source: string;
  lookup_timestamp: string;
  risk_flag: string;
  risk_types: string;
  dns_resolves?: boolean | null;
  dns_nxdomain?: boolean | null;
  http_status?: number | null;
  http_final_url?: string | null;
  tls_org?: string | null;
  tls_valid_to?: string | null;
  vt_malicious?: boolean | null;
  evidence_file: string;
}

const Index = () => {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [results, setResults] = useState<WhoisResult[]>([]);
  const [isChecking, setIsChecking] = useState(false);
  const [progress, setProgress] = useState(0);

  const handleFileUpload = (uploadedDomains: Domain[]) => {
    setDomains(uploadedDomains);
    setResults([]);
    setProgress(0);
  };

  const runChecks = async () => {
    if (domains.length === 0) {
      toast.error("Please upload a CSV file first");
      return;
    }

    setIsChecking(true);
    setProgress(0);
    setResults([]);

    try {
      // Create CSV content from domains
      const csvContent = "domain_name\n" + domains.map(d => d.domain_name).join("\n");
      const blob = new Blob([csvContent], { type: "text/csv" });
      const file = new File([blob], "domains.csv", { type: "text/csv" });

      // Create FormData and append the file
      const formData = new FormData();
      formData.append("file", file);

      // Call the bulk-domain-check endpoint
      const response = await fetch(
        `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/bulk-domain-check`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
          },
          body: formData,
        }
      );

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to check domains");
      }

      const data = await response.json();
      setResults(data.results || []);
      setProgress(100);
      toast.success(`Successfully checked ${domains.length} domain(s)`);
    } catch (error) {
      console.error("Error running checks:", error);
      toast.error(error instanceof Error ? error.message : "Failed to run domain checks. Please try again.");
    } finally {
      setIsChecking(false);
    }
  };

  const downloadCSV = () => {
    if (results.length === 0) {
      toast.error("No results to download");
      return;
    }

    const headers = [
      "domain_name",
      "registrant_name",
      "registrant_org",
      "registrar",
      "registry",
      "creation_date",
      "expiry_date",
      "nameservers",
      "data_source",
      "lookup_timestamp",
      "risk_flag",
      "risk_types",
      "dns_resolves",
      "dns_nxdomain",
      "http_status",
      "http_final_url",
      "tls_org",
      "tls_valid_to",
      "vt_malicious",
      "evidence_file",
    ];

    const csvContent = [
      headers.join(","),
      ...results.map((result) =>
        headers
          .map((header) => {
            const value = result[header as keyof WhoisResult] ?? "";
            return `"${String(value).replace(/"/g, '""')}"`;
          })
          .join(",")
      ),
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `nova-dominium-results-${new Date().toISOString().split("T")[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);

    toast.success("CSV downloaded successfully");
  };

  // Calculate summary stats
  const summaryStats = {
    total: results.length,
    green: results.filter((r) => r.risk_flag === "green").length,
    amber: results.filter((r) => r.risk_flag === "amber").length,
    red: results.filter((r) => r.risk_flag === "red").length,
    missingData: results.filter((r) => !r.expiry_date || !r.registrar).length,
    nxdomain: results.filter((r) => r.dns_nxdomain).length,
    httpUnreachable: results.filter((r) => !r.http_status).length,
    tlsPresent: results.filter((r) => !!r.tls_org).length,
  };

  return (
    <div className="min-h-screen bg-muted/30">
      {/* Top Navigation Bar */}
      <nav className="bg-slate-900 text-slate-50 h-14 flex items-center justify-between px-8 sticky top-0 z-50">
        <h1 className="text-base font-medium tracking-wide uppercase">
          Nova Dominium
        </h1>
        <div className="flex items-center gap-6">
          <button className="text-sm hover:text-slate-300 transition-colors">
            History
          </button>
          <button className="text-sm hover:text-slate-300 transition-colors">
            Settings
          </button>
        </div>
      </nav>

      {/* Main Content - Two Column Layout */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex flex-col lg:flex-row gap-8">
          {/* Left Column - Summary Card */}
          <aside className="w-full lg:w-64 flex-shrink-0">
            <SummaryCard {...summaryStats} />
          </aside>

          {/* Right Column - Hero + Results */}
          <div className="flex-1 space-y-6">
            {/* Hero Section */}
            <div className="space-y-2 mb-6">
              <h2 className="text-3xl font-bold text-foreground">
                Nova Dominium
              </h2>
              <p className="text-muted-foreground">Domain due-diligence &amp; ownership intelligence</p>
            </div>

            {/* Upload Card */}
            <Card className="p-8 flex flex-col items-center text-center space-y-4 shadow-[var(--shadow-card)]">
              <CloudUpload className="w-12 h-12 text-primary" />
              <h3 className="text-lg font-semibold text-foreground">
                Upload a CSV file containing domain names
              </h3>
              <p className="text-sm text-muted-foreground max-w-md">
                Upload a .csv file with a column named{" "}
                <code className="px-1.5 py-0.5 bg-muted rounded text-xs">
                  domain_name
                </code>
              </p>
              <FileUpload onUpload={handleFileUpload} />
              <Button
                onClick={runChecks}
                disabled={isChecking || domains.length === 0}
                className="mt-4 px-8"
                size="lg"
              >
                {isChecking ? "Checking domains..." : "Run Domain Checks"}
              </Button>
            </Card>

            {/* Domain Preview (if uploaded) */}
            {domains.length > 0 && (
              <Card className="p-6 shadow-[var(--shadow-card)]">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold uppercase tracking-wide">
                    Uploaded Domains ({domains.length})
                  </h3>
                </div>
                <DomainTable domains={domains} />
                {isChecking && (
                  <div className="mt-4">
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-primary to-accent transition-all duration-300"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                    <p className="text-sm text-muted-foreground mt-2 text-center">
                      Checking domains... {progress}%
                    </p>
                  </div>
                )}
              </Card>
            )}

            {/* Results Table */}
            {results.length > 0 && (
              <Card className="p-6 shadow-[var(--shadow-card)]">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold uppercase tracking-wide">
                    WHOIS Results ({results.length})
                  </h3>
                  <Button
                    onClick={downloadCSV}
                    variant="outline"
                    size="sm"
                    className="border-primary text-primary hover:bg-primary hover:text-primary-foreground"
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Download CSV
                  </Button>
                </div>
                <ResultsTable results={results} />
              </Card>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default Index;
