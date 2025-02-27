"use client";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <h1 className="text-3xl font-bold">Welcome to Secure Password Manager</h1>
      <button
        onClick={() => router.push("/dashboard")}
        className="mt-4 bg-blue-500 text-white px-4 py-2 rounded"
      >
        Access Passwords
      </button>
    </div>
  );
}
