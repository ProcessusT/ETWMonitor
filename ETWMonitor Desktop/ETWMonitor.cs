using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Toolkit.Uwp.Notifications;
using System.ServiceProcess;

namespace ETWMonitor
{
    public class ETWMonitor
    {




        public static void Alert(string message)
        {
            
            new ToastContentBuilder()
                    .AddText(message)
                    .Show();
        }




        public static void Service()
        {
            /*string serviceName = "ETWMonitor";

            ServiceController[] services = ServiceController.GetServices();
            bool isInstalled = false;
            foreach (ServiceController service in services)
            {
                if (service.ServiceName == serviceName)
                    isInstalled = true;
            }

            if(isInstalled == false)
            {
                var directory = Directory.GetCurrentDirectory();
                var destinationDirectory = Path.Combine(directory, "ETWMonitor.exe");

                System.Diagnostics.Process process = new System.Diagnostics.Process();
                System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                startInfo.FileName = "cmd.exe";
                startInfo.Arguments = "/C sc create " + serviceName + " binpath= " + destinationDirectory.ToString() + " start=auto";
                process.StartInfo = startInfo;
                process.Start();

                Alert("ETWMonitor is now installed.\nPlease restart your computer.");
                Environment.Exit(0);
            }*/
            Console.WriteLine("Service is use only in client-server version");
        }




        public static void Monitor()
        {

            Alert("ETWMonitor was started !");

            if (!(TraceEventSession.IsElevated() ?? false))
            {
                // need to be run as administrator
                return;
            }

            var existingSessions = TraceEventSession.GetActiveSessionNames();
            Console.WriteLine(existingSessions);

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
                    Console.WriteLine(data.ToString());



                    /*  
                     *  ####    WINRM   ####
                     */
                    if (data.ToString().ToLower().Contains("microsoft-windows-winrm") && data.ToString().ToLower().Contains("réponse HTTP 401 au client et déconnexion de la connexion"))
                    {   // Tentative de connexion WinRM
                        Alert("Tentative de connexion WinRM détectée");
                        Console.WriteLine("Tentative de connexion WinRM détectée");
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

                        Console.WriteLine("Connexion WinRM active en cours");
                        Console.WriteLine("USERNAME : " + ip_source.ToString());
                    }




                    /*  
                     *  ####    RPC   ####
                     */
                    if (data.ToString().ToLower().Contains("smb2requesttreeconnect") && data.ToString().ToLower().Contains("ipc$"))
                    {   // Tentative de connexion RPC

                        Alert("Tentative d'énumération RPC détectée");
                        Console.WriteLine("Tentative de connexion RPC détectée");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("lsarpc"))
                    {   // Connexion RPC au processus LSA

                        Alert("Connexion RPC au processus LSA");
                        Console.WriteLine("Connexion RPC au processus LSA");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("svcctl"))
                    {   // Connexion RPC au gestionnaire de service

                        Alert("Connexion RPC au gestionnaire de services\nPotentielle attaque PSEXEC détectée");
                        Console.WriteLine("Connexion RPC au gestionnaire de services");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("atsvc"))
                    {   // Connexion RPC au gestionnaire de service

                        Alert("Connexion RPC au gestionnaire de tâches planifiées\nPotentielle attaque ATEXEC détectée");
                        Console.WriteLine("Connexion RPC au gestionnaire de tâches planifiées");
                    }
                    if (data.ToString().ToLower().Contains("smb2requestcreate") && data.ToString().ToLower().Contains("spoolss"))
                    {   // Connexion RPC au spouleur d'impressions

                        Alert("Connexion RPC au spouleur d'impressions");
                        Console.WriteLine("Connexion RPC au spouleur d'impressions");
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

                        Console.WriteLine("Tentative de connexion RDP détectée");
                        Console.WriteLine("IP SOURCE : " + ip_source.ToString());

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

                        Console.WriteLine("Tentative de connexion SMB détectée");
                        Console.WriteLine("IP SOURCE : " + ip_source.ToString());
                    }
                    if (data.ToString().ToLower().Contains("smb2sessionauthenticated"))
                    {   // Connexion SMB réussie
                        // Detect also RPC over SMB and WMI over SMB

                        int client_name = data.ToString().IndexOf("UserName=\"") + 10;
                        string ip_source = data.ToString().Substring(client_name);
                        int client_name_length = ip_source.ToString().IndexOf("\"");
                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();

                        Alert("Connexion SMB active en cours\nUsername : " + ip_source);

                        Console.WriteLine("Connexion SMB active en cours");
                        Console.WriteLine("USERNAME : " + ip_source.ToString());
                    }


                };

                session.Source.Process();
            }

        }






        public static void Main(string[] args){

            try{
                new Thread(() => new Form1().ShowDialog()).Start();
            }
            catch{
                Console.WriteLine("Form can't be displayed from service.");
            }

            try{
                Service();
            }
            catch{
                Console.WriteLine("Error while creating service.");
            }

            Monitor();

        }




    }
}