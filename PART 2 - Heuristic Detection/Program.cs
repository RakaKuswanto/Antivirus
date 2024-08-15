// Raka Kuswanto - 2024
// Simple Antivirus

// Changelog
// Penambahan teknik heuristik untuk mendeteksi

using System;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;
using PeNet;

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
    /// Melakukan deteksi apakah file executable mengimpor fungsi tertentu, misalnya VirtualAlloc.
    /// </summary>
    public static bool ContainsFunction(string filePath, string functionName)
    {
        try
        {
            var peFile = new PeFile(filePath);

            // Periksa apakah fungsi diimpor dari tabel impor
            foreach (var importedFunction in peFile.ImportedFunctions)
            {
                if (importedFunction.Name != null && importedFunction.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"Error analyzing file {filePath}: {ex.Message}");
        }

        return false;
    }

    /// <summary>
    /// Melakukan deteksi heuristik pada file untuk menentukan apakah file mencurigakan.
    /// </summary>
    public static bool HeuristicAnalysis(string filePath, List<string> blacklistFunctions)
    {
        FileInfo fileInfo = new FileInfo(filePath);

        // Contoh Heuristik: Nama file yang mencurigakan
        string fileName = fileInfo.Name.ToLower();
        if (fileName.EndsWith(".exe") && (fileName.Contains("crack") || fileName.Contains("keygen") || fileName.Contains("hack")))
        {
            return true;
        }

        // Contoh Heuristik: Periksa header file
        using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            byte[] buffer = new byte[2];
            stream.Read(buffer, 0, 2);
            string fileHeader = BitConverter.ToString(buffer);

            // Periksa jika file ini adalah executable
            if (fileHeader == "4D-5A") // 'MZ' header untuk file EXE
            {
                foreach (var functionName in blacklistFunctions)
                {
                    if (ContainsFunction(filePath, functionName))
                    {
                        return true;
                    }
                }
            }
        }

        // Jika tidak ada kriteria heuristik yang terpenuhi, file dianggap aman
        return false;
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
    /// Memuat daftar fungsi yang dilarang dari file dan menyimpannya dalam List.
    /// </summary>
    public static List<string> LoadBlacklistFunctions(string filePath)
    {
        var blacklistFunctions = new List<string>();

        foreach (var line in File.ReadAllLines(filePath))
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                blacklistFunctions.Add(line.Trim());
            }
        }

        return blacklistFunctions;
    }

    /// <summary>
    /// Scan folder yang ditentukan dan subdirektorinya untuk mencari file, memeriksa setiap file apakah mengandung virus dengan membandingkan hash-nya dengan signature yang diketahui, dan mencetak peringatan jika virus terdeteksi.
    /// </summary>
    /// <param name="folderPath">Path ke folder yang akan dipindai.</param>
    /// <param name="signatures">Dictionary yang berisi signature virus yang diketahui.</param>
    public static void ScanFolder(string folderPath, Dictionary<string, string> signatures, List<string> blacklistFunctions)
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

            // Analisis heuristik pada file
            bool isSuspicious = HeuristicAnalysis(file, blacklistFunctions);
            if (isSuspicious)
            {
                Console.WriteLine($"Alert: {Path.GetFileName(file)} dianggap mencurigakan berdasarkan analisis heuristik.");
            }
        }
    }

    public static void Main()
    {
        string signatureFilePath = "signature_database.txt";
        string blacklistFunctionFilePath = "blacklist_function.txt";

        Dictionary<string, string> signatures = LoadSignatures(signatureFilePath);
        List<string> blacklistFunctions = LoadBlacklistFunctions(blacklistFunctionFilePath);

        Console.WriteLine("Masukkan path folder untuk dipindai:");
        string folderPath = Console.ReadLine();

        ScanFolder(folderPath, signatures, blacklistFunctions);

        Console.Read();
    }
}
