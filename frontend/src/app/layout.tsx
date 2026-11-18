import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DA005 | Sentinel Lab — Security Operations Console",
  description:
    "Ứng dụng AI trong phân tích nhật ký hệ thống và phát hiện tấn công (DA005 / TDTU)",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="vi" className="dark">
      <body className="min-h-screen bg-canvas font-sans text-slate-100 antialiased">
        {children}
      </body>
    </html>
  );
}
