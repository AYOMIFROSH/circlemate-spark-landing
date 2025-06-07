// WaitlistDashboard.tsx

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
  const res = await fetch(`${API_BASE}/api/waitlist`);
  const wrapper = await res.json();
  if (!res.ok) {
    const msg = wrapper.message || wrapper.error || "Failed to fetch waitlist";
    throw new Error(msg);
  }
  return wrapper.data;
};

const ADMIN_PASSCODE = "3820"; // You can change this or store in env

const WaitlistDashboard: React.FC = () => {
  const [entries, setEntries] = useState<WaitlistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [passcode, setPasscode] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!authorized) return;

    const load = async () => {
      try {
        const data = await fetchWaitlist();
        setEntries(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    load();
  }, [authorized]);

  const handlePasscodeSubmit = () => {
    if (passcode === ADMIN_PASSCODE) {
      setAuthorized(true);
      setError("");
    } else {
      setError("Incorrect passcode.");
    }
  };

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return entries.filter(
      (e) =>
        e.firstName.toLowerCase().includes(q) ||
        e.lastName.toLowerCase().includes(q) ||
        e.email.toLowerCase().includes(q)
    );
  }, [entries, query]);

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
                onChange={(e) => setQuery(e.target.value)}
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
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="animate-spin w-6 h-6 text-gray-500" />
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
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-10 text-gray-500">
                        No submissions found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((entry, i) => (
                      <TableRow key={entry.id} className="hover:bg-gray-50">
                        <TableCell>{i + 1}</TableCell>
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
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default WaitlistDashboard;
