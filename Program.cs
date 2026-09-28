using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using System.ComponentModel.DataAnnotations;

public class PasswordEntry
{
    public string Title { get;set; } = "";
    public string Username { get;set; } = "";
    public string Password { get;set; } = "";
    public string URL { get;set; } = "";
    public DateTime CreatedAt { get;set; } = DateTime.Now;
}

class Program
{
    private const string FilePath = "vault.json";
    private static List<PasswordEntry> vault = new();

    static void Main(string[] args)
    {
        if (!File.Exists(FilePath))
        {
            File.WriteAllText(FilePath, "[]");
        }

        vault = LoadVault();

        bool running = true;
        while (running)
        {
            Console.Clear();
            Console.WriteLine("1. View Passwords");
            Console.WriteLine("2. Add Entry");
            Console.WriteLine("3. Exit");
            Console.WriteLine("4. Delete Entry");
            Console.Write("\nSelect an option: ");

            string? selection = Console.ReadLine();

            switch(selection)
            {
                case "1":
                    ViewPasswords();
                    break;
                case "2":
                    AddEntry();
                    break;
                case "3":
                    Console.WriteLine("\nAdios!");
                    running = false;
                    break;
                case "4":
                    DeleteEntry();
                    break;
                default:
                    Console.WriteLine("\nInvalid option try again broski");
                    Console.ReadKey();
                    break;
            }
        }
    }
    private static List<PasswordEntry> LoadVault()
    {
        string json = File.ReadAllText(FilePath);
        List<PasswordEntry>? loaded = JsonSerializer.Deserialize<List<PasswordEntry>>(json);
        return loaded ?? new List<PasswordEntry>();
    }
    private static void SaveVault()
    {
        var options = new JsonSerializerOptions { WriteIndented = true};
        string json = JsonSerializer.Serialize(vault, options);
        File.WriteAllText(FilePath, json);
    }
    private static void AddEntry()
    {
        Console.Clear();
        Console.WriteLine("ADD NEW ENTRY");
        
        Console.Write("Title/Service Name: ");
        string title = Console.ReadLine() ?? "";
    
        Console.Write("Username / Email: ");
        string username = Console.ReadLine() ?? "";

        Console.Write("Password: ");
        string password = Console.ReadLine() ?? "";

        Console.Write("URL (Optional): ");
        string url = Console.ReadLine() ?? "";

        var entry = new PasswordEntry
        {
            Title = title,
            Username = username,
            Password = password,
            URL = url,
            CreatedAt = DateTime.Now
        };
        
        vault.Add(entry);
        SaveVault();

        Console.WriteLine("\nEntry added and saved.");
            Console.WriteLine("Press any key to return to menu");
            Console.ReadKey();

    }
    
    private static void ViewPasswords()
    {
        Console.Clear();
        Console.WriteLine("Saved Passwords\n");
        
        if (vault.Count == 0)
        {
            Console.WriteLine("No entries yet.");
        }
        else
        {
            for (int i=0; i < vault.Count; i++)
            {
                var entry = vault[i];
                Console.WriteLine($"{i+1}. {entry.Title}");
                Console.WriteLine($"    Username: {entry.Username}");
                Console.WriteLine($"    Password: {entry.Password}");
                Console.WriteLine($"    URL: {entry.URL}");
                Console.WriteLine();
            }
        }
    }
    private static void DeleteEntry()
    {
        Console.Clear();
        Console.WriteLine("Delete Entry\n");

        if (vault.Count == 0)
        {
            Console.WriteLine("No entries to delete");
            Console.WriteLine("Press any key to return to the menu");
            Console.ReadKey();
            return;
        }

        for (int i = 0; i < vault.Count; i++)
        {
            Console.WriteLine($"{i + 1}. {vault[i].Title}");
        }
        
        Console.Write("\nEnter the number of the entry you want to delete: ");
        string? input = Console.ReadLine();

        if (int.TryParse(input, out int number) &&
            number >= 1 &&
            number <= vault.Count)
        {
            vault.RemoveAt(number - 1);
            SaveVault();

            Console.WriteLine("\nEntry Deleted");
        }
        else
        {
            Console.WriteLine("\nInvalid Entry Number.");
        }

    Console.WriteLine("Press any key to return to the menu");
        Console.ReadKey();
    }
    
}
