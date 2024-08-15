// Raka Kuswanto - 2024
// Simple Antivirus

using System;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;

public class Antivirus
{
    /// <summary>
    /// Menghitung hash SHA256 dari file yang terletak pada path file yang ditentukan.
    /// </summary>
    /// <param name="filePath">Path ke file yang akan dihitung hash-nya.</param>
    /// <returns>Hash SHA256 dari file sebagai string heksadesimal.</returns>
    public static string ComputeFileHash(string filePath)
    {
        using (FileStream stream = File.OpenRead(filePath))
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
        }
    }

    /// <summary>
    /// Memeriksa apakah sebuah file mengandung virus dengan membandingkan hash-nya dengan tanda tangan virus yang diketahui.
    /// </summary>
    /// <param name="filePath">Path file yang akan diperiksa.</param>
    /// <param name="signatures">Dictionary yang berisi tanda tangan virus yang diketahui, di mana kunci adalah nama virus dan nilai adalah hash yang sesuai.</param>
    /// <returns>Nama virus jika ditemukan kecocokan, atau null jika tidak ditemukan kecocokan.</returns>
    public static string CheckForVirus(string filePath, Dictionary<string, string> signatures)
    {
        string fileHash = ComputeFileHash(filePath);
        foreach (var signature in signatures)
        {
            if (signature.Value.ToUpperInvariant() == fileHash)
            {
                return signature.Key;
            }
        }
        return null;
    }

    /// <summary>
    /// Memuat signature virus dari sebuah file dan menyimpannya dalam dictionary.
    /// </summary>
    /// <param name="filePath">Path ke file yang berisi signature.</param>
    /// <returns>Sebuah dictionary di mana kunci adalah nama virus dan nilai adalah hash yang sesuai.</returns>
    public static Dictionary<string, string> LoadSignatures(string filePath)
    {
        var signatures = new Dictionary<string, string>();

        foreach (var line in File.ReadAllLines(filePath))
        {
            var parts = line.Split(',');

            if (parts.Length == 2)
            {
                signatures[parts[0]] = parts[1];
            }
        }

        return signatures;
    }

    /// <summary>
    /// Scan folder yang ditentukan dan subdirektorinya untuk mencari file, memeriksa setiap file apakah mengandung virus dengan membandingkan hash-nya dengan signature yang diketahui, dan mencetak peringatan jika virus terdeteksi.
    /// </summary>
    /// <param name="folderPath">Path ke folder yang akan dipindai.</param>
    /// <param name="signatures">Dictionary yang berisi signature virus yang diketahui.</param>
    public static void ScanFolder(string folderPath, Dictionary<string, string> signatures)
    {
        // Mendapatkan semua file di folder yang ditentukan dan subdirektorinya
        var files = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories);

        // Melakukan iterasi pada setiap file
        foreach (var file in files)
        {
            // Cetak nama file yang sedang dipindai
            Console.WriteLine($"Scan file: {file}");

            // Memeriksa file apakah mengandung virus
            string namaVirus = CheckForVirus(file, signatures);

            // Jika virus terdeteksi, cetak peringatan
            if (namaVirus != null)
            {
                Console.WriteLine($"Alert: {Path.GetFileName(file)} terdeteksi sebagai virus! - Virus Name: {namaVirus}");
            }
        }
    }

    public static void Main()
    {
        string signatureFilePath = "signature_database.txt";
        Dictionary<string, string> signatures = LoadSignatures(signatureFilePath);

        Console.WriteLine("Masukkan path folder untuk dipindai:");
        string folderPath = Console.ReadLine();

        ScanFolder(folderPath, signatures);
        Console.Read();
    }
}
