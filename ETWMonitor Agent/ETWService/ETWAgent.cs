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

        

    public void Alert(string message, int level)
        {
            
            try
            {
                string settings = "";
                foreach (string line in System.IO.File.ReadLines(directory + "\\settings.conf"))
                {
                    settings += line;
                }

                int server_ip_index = settings.ToString().IndexOf("SERVER_IP=") + 10;
                string server_ip = settings.ToString().Substring(server_ip_index);
                int server_ip_end_index = server_ip.ToString().IndexOf(";");
                server_ip = server_ip.ToString().Substring(0, server_ip_end_index).Trim();
                
                int token_index = settings.ToString().IndexOf("TOKEN=") + 6;
                string token = settings.ToString().Substring(token_index);
                int token_end_index = token.ToString().IndexOf(";");
                token = token.ToString().Substring(0, token_end_index).Trim();

                var values = new Dictionary<string, string>
                {
                    { "hostname", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(hostname) ) },
                    { "message", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(message) ) },
                    { "level", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(level.ToString()) ) },
                    { "token", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(token) ) }
                };
                var content = new FormUrlEncodedContent(values);
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

            Alert("ETWMonitor was started !", 0);

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
                        Alert("Tentative de connexion WinRM détectée", 3);
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

                        Alert("Active WinRM connection detected\nFrom : " + ip_source + "\nUsername: " + sub_username, 5);

                    }




                    /*  
                     *  ####    RPC   ####
                     */
                    if (data.ToString().ToLower().Contains("smb2requesttreeconnect") && data.ToString().ToLower().Contains("ipc$"))
                    {   // Tentative de connexion RPC

                        Alert("RPC enumeration attempt detected", 2);
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("lsarpc"))
                    {   // Connexion RPC au processus LSA

                        Alert("RPC connection to LSA process", 5);
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("svcctl"))
                    {   // Connexion RPC au gestionnaire de service

                        Alert("RPC connection to service manager\nPotential PSEXEC attack detected", 5);
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("atsvc"))
                    {   // Connexion RPC au gestionnaire de service

                        Alert("RPC connection to scheduled task manager\nPotential ATEXEC attack detected", 5);
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("spoolss"))
                    {   // Connexion RPC au spouleur d'impressions

                        Alert("RPC connection to print spooler", 5);
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

                        Alert("RDP connection attempt detected\nFrom : " + ip_source, 3);


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

                        Alert("SMB connection attempt detected\nFrom : " + ip_source, 3);

                    }
                    if (data.ToString().ToLower().Contains("smb2sessionauthenticated"))
                    {   // Connexion SMB réussie
                        // Detect also RPC over SMB and WMI over SMB

                        int client_name = data.ToString().IndexOf("UserName=\"") + 10;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf("\"");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        Alert("Active SMB connection detected\nUsername : " + ip_source, 5);

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
