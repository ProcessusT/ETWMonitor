using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.ServiceProcess;

namespace ETWService
{
    public partial class ETWAgent : ServiceBase
    {
        public ETWAgent()
        {
            InitializeComponent();
        }


        private static readonly HttpClient client = new HttpClient();

        
        string hostname = Dns.GetHostName();
        string directory = "";

        

    public void Alert(string message)
        {
            

            var values = new Dictionary<string, string>
            {
                { "hostname", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(hostname) ) },
                { "message", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(message) ) }
            };
            try
            {
                File.WriteAllText(directory + "\\ETW.log", directory);
                string server_ip = "";
                var content = new FormUrlEncodedContent(values);
                foreach (string line in System.IO.File.ReadLines(directory + "\\server_ip.conf"))
                {
                    server_ip += line;
                }
                File.WriteAllText(directory + "\\ETW.log", server_ip);
                var response = client.PostAsync("http://" + server_ip.Trim() + "/collector.php", content);
                var responseString = response.Result.ToString();
            }
            catch
            {
                File.WriteAllText(directory + "\\ETW.log", "Error while reading app config file.");
            }

        }



        public void Monitor()
        {

            Alert("ETWMonitor was started !");

            if (!(TraceEventSession.IsElevated() ?? false))
            {
                // need to be run as administrator
                return;
            }

            var existingSessions = TraceEventSession.GetActiveSessionNames();
            
            var sessionName = "ETWMonitor";

            using (var session = new TraceEventSession(sessionName))
            {

                // For ETW providers list go to : https://github.com/repnz/etw-providers-docs

                // ETW Providers on Windows 10 for SMB (and RPC)
                session.EnableProvider(new Guid("{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}"));

                // ETW Providers on Windows 10 for RDP
                session.EnableProvider(new Guid("{1139c61b-b549-4251-8ed3-27250a1edec8}"));

                // ETW Providers on Windows 10 for WinRM
                session.EnableProvider(new Guid("{a7975c8f-ac13-49f1-87da-5a984a4ab417}"));


                session.Source.Dynamic.All += delegate (TraceEvent data)
                {
                    var delay = (DateTime.Now - data.TimeStamp).TotalSeconds;


                    /*FOR DEBUGGING
                    if (data.ToString().ToLower().Contains("ATTACKER IP")){
                        Console.WriteLine(data.ToString());
                    }*/



                    /*  
                     *  ####    WINRM   ####
                     */
                    if (data.ToString().ToLower().Contains("microsoft-windows-winrm") && data.ToString().ToLower().Contains("réponse HTTP 401 au client et déconnexion de la connexion"))
                    {   // Tentative de connexion WinRM
                        Alert("Tentative de connexion WinRM détectée");
                    }
                    if (data.ToString().ToLower().Contains("microsoft-windows-winrm") && data.ToString().ToLower().Contains("création") && data.ToString().ToLower().Contains("interpréteur de commande wsman sur le serveur"))
                    {   // Connexion WinRM réussie

                        int client_name = data.ToString().IndexOf("clientIP: ") + 10;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf(")");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        int username = data.ToString().IndexOf("PowerShell (") + 12;
                        string sub_username = data.ToString().Substring(username);
                        int username_length = sub_username.ToString().IndexOf(" ");
                        sub_username = sub_username.ToString().Substring(0, username_length).Trim();

                        Alert("Connexion WinRM active en cours\nDepuis : " + ip_source + "\nUsername: " + sub_username);

                    }




                    /*  
                     *  ####    RPC   ####
                     */
                    if (data.ToString().ToLower().Contains("smb2requesttreeconnect") && data.ToString().ToLower().Contains("ipc$"))
                    {   // Tentative de connexion RPC

                        Alert("Tentative d'énumération RPC détectée");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("lsarpc"))
                    {   // Connexion RPC au processus LSA

                        Alert("Connexion RPC au processus LSA");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("svcctl"))
                    {   // Connexion RPC au gestionnaire de service

                        Alert("Connexion RPC au gestionnaire de services\nPotentielle attaque PSEXEC détectée");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("atsvc"))
                    {   // Connexion RPC au gestionnaire de service

                        Alert("Connexion RPC au gestionnaire de tâches planifiées\nPotentielle attaque ATEXEC détectée");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("spoolss"))
                    {   // Connexion RPC au spouleur d'impressions

                        Alert("Connexion RPC au spouleur d'impressions");
                    }




                    /*  
                     *  ####    RDP   ####
                     */
                    if (data.ToString().ToLower().Contains("microsoft-windows-remotedesktopservices-rdpcorets\" formattedmessage=\"le serveur a accepté une nouvelle connexion tcp du client"))
                    { // Tentative de connexion RDP

                        int client_name = data.ToString().IndexOf("ClientIP=\"") + 10;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf(":");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        Alert("Tentative de connexion RDP détectée\nSource : " + ip_source);


                    }




                    /*  
                     *  ####    SMB   ####
                     */
                    if (data.ToString().ToLower().Contains("smb2connectionaccept/démarrer"))
                    {   // Tentative de connexion SMB
                        // Detect also RPC over SMB and WMI over SMB

                        int client_name = data.ToString().IndexOf("Address=\"") + 9;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf(":");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        Alert("Tentative de connexion SMB détectée\nSource : " + ip_source);

                    }
                    if (data.ToString().ToLower().Contains("smb2sessionauthenticated"))
                    {   // Connexion SMB réussie
                        // Detect also RPC over SMB and WMI over SMB

                        int client_name = data.ToString().IndexOf("UserName=\"") + 10;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf("\"");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        Alert("Connexion SMB active en cours\nUsername : " + ip_source);

                    }


                };

                session.Source.Process();
            }

        }

        protected override void OnStart(string[] args)
        {

            string service_name = "ETWMonitor Agent";
            string imagepath = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + service_name, "ImagePath", string.Empty).ToString();
            int imagepath_length = imagepath.ToString().LastIndexOf("\\");
            this.directory = imagepath.ToString().Substring(0, imagepath_length).Trim();

            Monitor();
        }

        protected override void OnStop()
        {

        }
    }
}
