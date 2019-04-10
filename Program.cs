using System;
using System.IO;
using System.Linq;

namespace DnsUpdater
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args == null || args.Length < 1)
            {
                Console.WriteLine("Please specify new IP address");
                Environment.Exit(1);
            }

            var newIpAddr = args[0];
            if (NotChanging(newIpAddr))
            {
                Console.WriteLine("Skipping updating, because IP did not change since last update. \nIf you think this is a mistake, please delete the 'last-updated.txt' file in the path of this program.");
                return;
            }
            

            var conf = ReadConfigurations();
            using (var updater = new AliDnsUpdater(conf[0], conf[2], conf[3]))
            {
                try
                {
                    updater.UpdateRecord(conf[1], newIpAddr);
                    File.WriteAllText(Path.Combine(GetBasePath(), "last-updated.txt"), newIpAddr);
                }
                catch (AliDnsUpdater.AliyunDnsException ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    Console.Error.WriteLine(ex.GetResponseMessage());
                    Console.Error.WriteLine(ex.StackTrace);
                }
            }
            Console.WriteLine($"Updated {conf[1]} to {newIpAddr}");
        }

        static string[] ReadConfigurations()
        {
            var confFile = Path.Combine(GetBasePath(), "config.txt");
            return File.ReadAllLines(confFile)
                .Select(l => l.Trim())
                .Where(l => !l.StartsWith("#"))
                .ToArray();
        }
        
        static bool NotChanging(string ip)
        {
            var lastUpdated = Path.Combine(GetBasePath(), "last-updated.txt");
            if (!File.Exists(lastUpdated))
            {
                return false;
            }

            return string.Equals(ip, File.ReadAllText(lastUpdated), StringComparison.OrdinalIgnoreCase);
        }

        private static string GetBasePath()
        {
            var basePath = Path.GetDirectoryName(typeof(Program).Assembly.Location);
            return basePath;
        }
    }
}
