using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

using Microsoft.Toolkit.Uwp.Notifications;

namespace ETWMonitor{
    public class ETWMonitor
    {

        public static void alert(string message)
        {
            new ToastContentBuilder()
                    .AddText(message)
                    .Show();
        }



        public static void Main(string[] args){


            alert("ETWMonitor was started !");


            if (!(TraceEventSession.IsElevated() ?? false)){
                Console.WriteLine("Please run as Administrator");
                alert("ETWMonitor need to be run as Administrator");
                return;
            }


            var existingSessions = TraceEventSession.GetActiveSessionNames();
            Console.WriteLine(existingSessions);

            var sessionName = "ETWMonitor";

            using (var session = new TraceEventSession(sessionName)){

                // For ETW providers list go to : https://github.com/repnz/etw-providers-docs

                // ETW Providers on Windows 10 for SMB
                session.EnableProvider(new Guid("{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}"));

                // ETW Providers on Windows 10 for RDP
                session.EnableProvider(new Guid("{1139c61b-b549-4251-8ed3-27250a1edec8}"));
                

                session.Source.Dynamic.All += delegate (TraceEvent data){     
                    var delay = (DateTime.Now - data.TimeStamp).TotalSeconds;


                    /* FOR DEBUGGING
                    if (data.ToString().ToLower().Contains("<YOUR_ATTACKER_IP_ADDRESS_HERE>")){
                        Console.WriteLine(data.ToString());
                    }
                    */



                    if (data.ToString().ToLower().Contains("smb2requesttreeconnect") && data.ToString().ToLower().Contains("ipc$"))
                    {   // Tentative de connexion RPC

                        alert("Tentative d'énumération RPC détectée");
                        Console.WriteLine("Tentative de connexion RPC détectée");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("lsarpc"))
                    {   // Connexion RPC au processus LSA

                        alert("Connexion RPC au processus LSA");
                        Console.WriteLine("Connexion RPC au processus LSA");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("svcctl"))
                    {   // Connexion RPC au gestionnaire de service

                        alert("Connexion RPC au gestionnaire de services\nPotentielle attaque PSEXEC détectée");
                        Console.WriteLine("Connexion RPC au gestionnaire de services");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("atsvc"))
                    {   // Connexion RPC au gestionnaire de service

                        alert("Connexion RPC au gestionnaire de tâches planifiées\nPotentielle attaque ATEXEC détectée");
                        Console.WriteLine("Connexion RPC au gestionnaire de tâches planifiées");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("spoolss"))
                    {   // Connexion RPC au spouleur d'impressions

                        alert("Connexion RPC au spouleur d'impressions");
                        Console.WriteLine("Connexion RPC au spouleur d'impressions");
                    }


                    if (data.ToString().ToLower().Contains("microsoft-windows-remotedesktopservices-rdpcorets\" formattedmessage=\"le serveur a accepté une nouvelle connexion tcp du client") == true)
                    { // Tentative de connexion RDP

                        int client_name = data.ToString().IndexOf("ClientIP=\"") + 10;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf(":");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        alert("Tentative de connexion RDP détectée\nSource : " + ip_source);

                        Console.WriteLine("Tentative de connexion RDP détectée");
                        Console.WriteLine("IP SOURCE : " + ip_source.ToString());

                    }


                    if (data.ToString().ToLower().Contains("smb2connectionaccept/démarrer") == true)
                    {   // Tentative de connexion SMB
                        // Detect also RPC over SMB and WMI over SMB

                        int client_name = data.ToString().IndexOf("Address=\"") + 9;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf(":");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        alert("Tentative de connexion SMB détectée\nSource : " + ip_source);

                        Console.WriteLine("Tentative de connexion SMB détectée");
                        Console.WriteLine("IP SOURCE : " + ip_source.ToString());
                    }
                    if (data.ToString().ToLower().Contains("smb2sessionauthenticated") == true)
                    {   // Connexion SMB réussie
                        // Detect also RPC over SMB and WMI over SMB

                        int client_name = data.ToString().IndexOf("UserName=\"") + 10;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf("\"");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        alert("Connexion SMB active en cours\nUsername : " + ip_source);

                        Console.WriteLine("Connexion SMB active en cours");
                        Console.WriteLine("USERNAME : " + ip_source.ToString());
                    }


                    



                };

                session.Source.Process();


                

            }
        }
    }
}