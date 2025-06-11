import React, { useEffect, useMemo, useState } from "react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loader2, Download } from "lucide-react";

interface WaitlistEntry {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  interest: string;
  createdAt: string;
}
const API_BASE =
  process.env.NODE_ENV === "production"
    ? "https://circlemate-spark-landing-jet.vercel.app"
    : "http://localhost:3000";

// Fetch wrapper: throw server-sent message if available
const fetchWaitlist = async (): Promise<WaitlistEntry[]> => {
  try {
    const res = await fetch(`${API_BASE}/api/v1/waitlist`);
    const wrapper = await res.json();
    if (!res.ok) {
      // Handle network/server errors with more detail
      if (res.status === 503 && (wrapper.code === 'NETWORK_UNAVAILABLE' || (wrapper.message && wrapper.message.toLowerCase().includes('network connection error')))) {
        throw new Error('Network connection error. Please check your internet connection and try again.');
      }
      const msg = wrapper.message || wrapper.error || `Failed to fetch waitlist (status ${res.status})`;
      throw new Error(msg);
    }
    if (wrapper.status !== 'success') {
      throw new Error(wrapper.message || 'Unknown error occurred');
    }
    return wrapper.data;
  } catch (err: any) {
    // Catch fetch/network errors
    if (err.name === 'TypeError' && err.message && err.message.includes('Failed to fetch')) {
      throw new Error('Unable to connect to the server. Please check your network.');
    }
    throw err;
  }
};

const ADMIN_PASSCODE = "3820"; // You can change this or store in env
const PAGE_SIZE = 20;

const WaitlistDashboard: React.FC = () => {
  const [entries, setEntries] = useState<WaitlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [passcode, setPasscode] = useState("");
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [isSlowNetwork, setIsSlowNetwork] = useState(false);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return entries.filter(
      (e) =>
        e.firstName.toLowerCase().includes(q) ||
        e.lastName.toLowerCase().includes(q) ||
        e.email.toLowerCase().includes(q)
    );
  }, [entries, query]);

  // Pagination logic
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [filtered, page]);

  useEffect(() => {
    if (!authorized) return;

    let slowNetworkTimer: NodeJS.Timeout;
    const load = async () => {
      setLoading(true);
      setIsSlowNetwork(false);
      slowNetworkTimer = setTimeout(() => setIsSlowNetwork(true), 2000); // 2s threshold
      try {
        const data = await fetchWaitlist();
        setEntries(data);
        setError("");
      } catch (err: any) {
        setError(err.message || "Failed to fetch waitlist");
      } finally {
        setLoading(false);
        clearTimeout(slowNetworkTimer);
      }
    };

    load();
    return () => clearTimeout(slowNetworkTimer);
  }, [authorized]);

  const handlePasscodeSubmit = () => {
    if (passcode === ADMIN_PASSCODE) {
      setAuthorized(true);
      setError("");
    } else {
      setError("Incorrect passcode.");
    }
  };

  const downloadCSV = () => {
    const header = ["First Name", "Last Name", "Email", "Interest", "Date"].join(",");
    const rows = entries
      .map((e) =>
        [
          e.firstName,
          e.lastName,
          e.email,
          e.interest,
          new Date(e.createdAt).toLocaleString(),
        ].join(",")
      )
      .join("\n");
    const csv = `${header}\n${rows}`;
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "waitlist.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!authorized) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 p-4">
        <div className="bg-white p-6 rounded-lg shadow-lg w-full max-w-sm">
          <h2 className="text-lg font-semibold mb-4">Enter Admin Passcode</h2>
          <Input
            type="password"
            value={passcode}
            onChange={(e) => setPasscode(e.target.value)}
            placeholder="Passcode"
            className="mb-3"
          />
          {error && <p className="text-sm text-red-600 mb-2">{error}</p>}
          <Button onClick={handlePasscodeSubmit} className="w-full">
            Access Dashboard
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <Card className="rounded-2xl shadow-lg">
        <CardHeader>
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <CardTitle className="text-2xl font-semibold">Waitlist Submissions</CardTitle>
            <div className="flex items-center gap-3 w-full sm:w-auto">
              <Input
                placeholder="Search by name or email…"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1); // Reset to first page on search
                }}
                className="max-w-xs"
              />
              <Button
                variant="outline"
                size="icon"
                onClick={downloadCSV}
                title="Export as CSV"
              >
                <Download className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isSlowNetwork && loading && (
            <div className="flex items-center justify-center py-2">
              <span className="text-yellow-600 font-medium">Loading is taking longer thank usual, Check your internet connection</span>
            </div>
          )}
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="animate-spin w-6 h-6 text-gray-500" />
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <span className="text-red-600 font-medium">{error}</span>
              <Button onClick={() => window.location.reload()} variant="outline">Retry</Button>
            </div>
          ) : (
            <div className="overflow-x-auto border rounded-lg">
              <Table>
                <TableHeader>
                  <TableRow className="bg-gray-50">
                    <TableHead className="w-16">#</TableHead>
                    <TableHead>First Name</TableHead>
                    <TableHead>Last Name</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Interest</TableHead>
                    <TableHead>Date</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paginated.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-10 text-gray-500">
                        No submissions found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    paginated.map((entry, i) => (
                      <TableRow key={entry.id} className="hover:bg-gray-50">
                        <TableCell>{(page - 1) * PAGE_SIZE + i + 1}</TableCell>
                        <TableCell>{entry.firstName}</TableCell>
                        <TableCell>{entry.lastName}</TableCell>
                        <TableCell>{entry.email}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="capitalize">
                            {entry.interest}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {new Date(entry.createdAt).toLocaleDateString()}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
              {/* Pagination Controls */}
              {totalPages > 1 && (
                <div className="flex justify-end items-center gap-2 mt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page === 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    Previous
                  </Button>
                  <span className="text-sm text-gray-600">
                    Page {page} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page === totalPages}
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  >
                    Next
                  </Button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default WaitlistDashboard;
