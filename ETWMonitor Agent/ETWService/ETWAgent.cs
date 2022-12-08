using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;

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
        string token = "";
        string server_ip = "";
        int crowdsec_integration = 0;
        ArrayList crowdsec_ip_adresses_list = new ArrayList();
        ArrayList whitelisted_ip_adresses = new ArrayList();
        private static System.Timers.Timer updateTimer;
        public Thread th;
        public TraceEventSession session;


        public void Alert(string message, int level)
        {
            try
            {   
                var values = new Dictionary<string, string>
                {
                    { "hostname", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(hostname) ) },
                    { "message", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(message) ) },
                    { "level", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(level.ToString()) ) },
                    { "token", System.Convert.ToBase64String( System.Text.Encoding.UTF8.GetBytes(this.token) ) }
                };
                var content = new FormUrlEncodedContent(values);
                var response = client.PostAsync("http://" + this.server_ip.Trim() + "/collector.php", content);
                var responseString = response.Result.ToString();
            }
            catch
            {
                File.AppendAllText(directory + "\\ETW.log", "Error while reading app config file."+"\n");
            }

        }



        public void Monitor()
        {
            Alert("ETWMonitor was started !", 0);
            File.WriteAllText(directory + "\\ETW.log", "ETWMonitor was started !\n");
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                // need to be run as administrator
                return;
            }
            ArrayList providers_list = new ArrayList();
            ArrayList alerts_list = new ArrayList();
            ArrayList images_list = new ArrayList();
            var process_loaded_dll = new Dictionary<string, List<string>>();

            try
            {
                string filename = directory + "\\rules.xml";
                XmlTextReader rules_file = new XmlTextReader(filename);
                rules_file.WhitespaceHandling = WhitespaceHandling.None;
                string xmlContent = "";
                while (rules_file.Read())
                {
                    switch (rules_file.NodeType)
                    {
                        case XmlNodeType.Element:
                            xmlContent += "<" + rules_file.Name + ">";
                            break;
                        case XmlNodeType.Text:
                            xmlContent += rules_file.Value;
                            break;
                        case XmlNodeType.EndElement:
                            xmlContent += "</" + rules_file.Name + ">";
                            break;
                    }
                }
                XmlDocument rules = new XmlDocument();
                rules.LoadXml(xmlContent);
                // get GUID providers
                XmlNodeList providers = rules.GetElementsByTagName("guid");
                foreach (XmlNode provider in providers)
                {
                    providers_list.Add(provider.InnerText);
                }
                // get all match detections
                XmlNodeList detection_rules = rules.GetElementsByTagName("detections");
                foreach (XmlNode detection_rule in detection_rules)
                {
                    foreach (XmlNode rule_name in detection_rule.ChildNodes)
                    {
                        var alert_matches = rules.SelectNodes(@"//" + rule_name.Name + "/match/string");
                        string alert_string = rules.SelectSingleNode(@"//" + rule_name.Name + "/alert").InnerText;
                        string alert_score = rules.SelectSingleNode(@"//" + rule_name.Name + "/score").InnerText;
                        ArrayList alert = new ArrayList()
                        {
                            alert_string, alert_score
                        };
                        foreach (XmlNode item in alert_matches)
                        {
                            alert.Add(item.InnerText);
                        }
                        var temp_alert = alert.ToArray();
                        alerts_list.Add(temp_alert);
                        
                    }
                }

                // get all loaded images 
                XmlNodeList loaded_images = rules.GetElementsByTagName("loaded-images");
                foreach (XmlNode image_rule in loaded_images)
                {
                    foreach (XmlNode rule_name in image_rule.ChildNodes)
                    {
                        var image_matches = rules.SelectNodes(@"//" + rule_name.Name + "/match/string");
                        string image_string = rules.SelectSingleNode(@"//" + rule_name.Name + "/alert").InnerText;
                        string image_score = rules.SelectSingleNode(@"//" + rule_name.Name + "/score").InnerText;
                        ArrayList image_alert = new ArrayList()
                        {
                            image_string, image_score
                        };

                        foreach (XmlNode item in image_matches)
                        {
                            image_alert.Add(item.InnerText);
                        }
                        var temp_alert = image_alert.ToArray();
                        images_list.Add(temp_alert);

                    }
                }


                // crowdsec integration
                XmlNodeList crowdsec_ip_adresses = rules.GetElementsByTagName("crowdsec");
                foreach (XmlNode ip_address in crowdsec_ip_adresses)
                {
                    foreach (XmlNode ip in ip_address.ChildNodes)
                    {
                        crowdsec_integration = 1;
                        crowdsec_ip_adresses_list.Add(ip.InnerText.Trim());
                    }
                }
                if(crowdsec_integration == 1)
                {
                    File.AppendAllText(directory + "\\ETW.log", "Crowdsec integration is activated\n");
                }
            }
            catch (Exception e)
            {
                File.AppendAllText(directory + "\\ETW.log", "Error while reading XML rules file : " + e.ToString()+"\n\n");
            }



            File.AppendAllText(directory + "\\ETW.log", "Starting ETW session...\n");

            var existingSessions = TraceEventSession.GetActiveSessionNames();
            var sessionName = "ETWMonitor";
            using (this.session = new TraceEventSession(sessionName))
            {
                // For ETW providers list go to : https://github.com/repnz/etw-providers-docs
                foreach(string provider in providers_list)
                {
                    session.EnableProvider(new Guid(provider));
                    File.AppendAllText(directory + "\\ETW.log", "Enable new guid provider : " + provider.ToString() + "\n");
                }

                File.AppendAllText(directory + "\\ETW.log", "Starting reading ETW...\n");
                session.Source.Dynamic.All += delegate (TraceEvent data)
                {


                    // Loaded images rules
                    if (data.ToString().ToLower().Contains("eventname=\"imageload"))
                    {
                        try
                        {
                            int pid = data.ToString().ToLower().IndexOf("pid=\"") + 5;
                            string threadID = data.ToString().Substring(pid);
                            int threadID_length = threadID.ToString().ToLower().IndexOf("\"");
                            threadID = threadID.ToString().Substring(0, threadID_length).Trim();

                            int imagename = data.ToString().ToLower().IndexOf("imagename=\"") + 11;
                            string dll_name = data.ToString().Substring(imagename);
                            int dll_name_length = dll_name.ToString().ToLower().IndexOf("\"");
                            dll_name = dll_name.ToString().Substring(0, dll_name_length).Trim();

                            Process proc = Process.GetProcessById(Int32.Parse(threadID));

                            File.AppendAllText(directory + "\\ETW.log", "proc analysé : " +proc.ProcessName.ToString()+ "\n");

                            if (!process_loaded_dll.Keys.Contains(proc.ProcessName))
                            {
                                process_loaded_dll.Add(proc.ProcessName, new List<string> { });
                            }

                            foreach (var process in process_loaded_dll)
                            {
                                try
                                {
                                    if (proc.ProcessName == process.Key)
                                    {
                                        if (!process.Value.Contains(dll_name.ToLower()))
                                        {
                                            process.Value.Add(dll_name.ToLower());
                                        }
                                        foreach (Array image_dll_rule in images_list.ToArray())
                                        {
                                            int i = 0;
                                            List<string> matches = new List<string>();
                                            string image_string = "";
                                            int image_score = 0;
                                            int nb_matches = -2;
                                            foreach (string item in image_dll_rule)
                                            {
                                                if (i == 0)
                                                {
                                                    image_string = item.ToString();
                                                }
                                                else if (i == 1)
                                                {
                                                    try
                                                    {
                                                        image_score = int.Parse(item);
                                                    }catch(Exception ex)
                                                    {
                                                        image_score = 0;
                                                    }
                                                }
                                                else
                                                {
                                                    matches.Add(item);
                                                }
                                                nb_matches = nb_matches + 1;
                                                i = i + 1;
                                            }
                                            int nb_bad_dll = 0;
                                            foreach (string dll in process.Value)
                                            {
                                                foreach (var bad_dll in matches)
                                                {
                                                    if (dll.ToLower().Contains(bad_dll.ToLower()))
                                                    {
                                                        nb_bad_dll = nb_bad_dll + 1;
                                                    }
                                                }
                                            }
                                            if (nb_bad_dll >= nb_matches)
                                            {
                                                Alert(image_string, image_score);
                                                /*
                                                // If you have balls, you can kill it 
                                                proc.Kill();
                                                proc.Close();
                                                proc.Dispose();
                                                */
                                            }
                                        }
                                    }
                                }
                                catch (Exception e)
                                {
                                    continue;
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("error in loaded images");
                        }
                    }







                    // Crowdsec rules
                    if (crowdsec_integration == 1)
                    {
                        var match = Regex.Match(data.ToString(), @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
                        if (match.Success)
                        {
                            string ip_string = match.Captures[0].ToString();

                            if (!whitelisted_ip_adresses.Contains(ip_string))
                            {
                                if (crowdsec_ip_adresses_list.Contains(ip_string))
                                {
                                    Alert("IP address reported by Crowdsec detected : " + ip_string.ToString(), 5);
                                    File.AppendAllText(directory + "\\ETW.log", "Find an ip address that match Crowdsec list : " + ip_string.ToString().ToLower() + "\n\n");
                                }
                                else
                                {
                                    whitelisted_ip_adresses.Add(ip_string);
                                    File.AppendAllText(directory + "\\ETW.log", "New ip address add to whitelist : " + ip_string.ToString().ToLower() + "\n\n");
                                }
                            }
                        }
                    }










                    // detection rules
                    foreach (Array alert in alerts_list.ToArray())
                    {
                        int i = 0;
                        string alert_msg = "";
                        int alert_score = 0;
                        // because 2 first items are msg and score
                        int sendAlert = 2;
                        foreach (string item in alert)
                        {
                            if (i == 0)
                            {
                                alert_msg = item.ToString();
                            }
                            else if (i == 1)
                            {
                                alert_score = int.Parse(item);
                            }
                            else
                            {
                                
                                if (data.ToString().ToLower().Contains(item.ToString().ToLower()))
                                {
                                    sendAlert++;
                                    // catch infos
                                    

                                    if (data.ToString().ToLower().Contains("filename=\"users") && sendAlert < 4)
                                    {
                                        try
                                        {
                                            int username = data.ToString().ToLower().IndexOf("filename=\"users") + 10;
                                            string username_smbclient = data.ToString().Substring(username);
                                            int username_smbclient_length = username_smbclient.ToString().ToLower().IndexOf("\" createcontextscount");
                                            username_smbclient = username_smbclient.ToString().Substring(0, username_smbclient_length).Trim();
                                            alert_msg = alert_msg + "\nCredentials folder : " + username_smbclient;
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                    if (data.ToString().ToLower().Contains("utilisateur = ") && sendAlert < 4)
                                    {
                                        try
                                        {
                                            int username = data.ToString().IndexOf("Utilisateur = ") + 14;
                                            string username_powershell = data.ToString().Substring(username);
                                            int username_powershell_length = username_powershell.ToString().IndexOf("Utilisateur");
                                            username_powershell = username_powershell.ToString().Substring(0, username_powershell_length).Trim();
                                            alert_msg = alert_msg + "\nby User : " + username_powershell;
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                    if (data.ToString().ToLower().Contains("build_report\" name=\"") && sendAlert<4)
                                    {
                                        try
                                        {
                                            int filedetect = data.ToString().IndexOf("build_report\" Name=\"") + 20;
                                            string filename_defender = data.ToString().Substring(filedetect);
                                            int filename_defender_length = filename_defender.ToString().IndexOf("\"");
                                            filename_defender = filename_defender.ToString().Substring(0, filename_defender_length).Trim();
                                            alert_msg = alert_msg + "\nFile : " + filename_defender;
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                    if (data.ToString().ToLower().Contains("clientip: ") && sendAlert < 4)
                                    {
                                        try
                                        {
                                            int client_name = data.ToString().IndexOf("clientIP: ") + 10;
                                            string ip_source = data.ToString().Substring(client_name);
                                            int client_name_length = ip_source.ToString().IndexOf(")");
                                            ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();
                                            int username = data.ToString().IndexOf("PowerShell (") + 12;
                                            string sub_username = data.ToString().Substring(username);
                                            int username_length = sub_username.ToString().IndexOf(" ");
                                            sub_username = sub_username.ToString().Substring(0, username_length).Trim();
                                            alert_msg = alert_msg + "\nFrom : " + ip_source + "\nUsername: " + sub_username;
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                    if (data.ToString().ToLower().Contains("clientip=\"") && sendAlert < 4)
                                    {
                                        try{
                                            int client_name = data.ToString().IndexOf("ClientIP=\"") + 10;
                                            string ip_source = data.ToString().Substring(client_name);
                                            int client_name_length = ip_source.ToString().IndexOf(":");
                                            ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();
                                            alert_msg = alert_msg + "\nFrom : " + ip_source;
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                    if (data.ToString().ToLower().Contains("address=\"") && sendAlert < 4)
                                    {
                                        try { 
                                            int client_name = data.ToString().IndexOf("Address=\"") + 9;
                                            string ip_source = data.ToString().Substring(client_name);
                                            int client_name_length = ip_source.ToString().IndexOf(":");
                                            ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();
                                            alert_msg = alert_msg + "\nFrom : " + ip_source;
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                    if (data.ToString().ToLower().Contains("username=\"") && sendAlert < 4)
                                    {
                                        try{
                                            int client_name = data.ToString().IndexOf("UserName=\"") + 10;
                                            string ip_source = data.ToString().Substring(client_name);
                                            int client_name_length = ip_source.ToString().IndexOf("\"");
                                            ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();
                                            alert_msg = alert_msg + "\nUsername : " + ip_source;
                                        }
                                        catch
                                        {
                                            continue;
                                        }
                                    }
                                }
                            }
                            i++;
                        }

                        if (sendAlert >= alert.Length)
                        {
                            File.AppendAllText(directory + "\\ETW.log", "Send alert :\n" + alert_msg + "\n" + "Details : " + data.ToString().ToLower() +"\n\n");
                            Alert(alert_msg, alert_score);
                        }
                    }
                };
                this.session.Source.Process();
            }
        }



        static bool FilesAreEqual_Hash(FileInfo first, FileInfo second)
        {
            byte[] firstHash = MD5.Create().ComputeHash(first.OpenRead());
            byte[] secondHash = MD5.Create().ComputeHash(second.OpenRead());
            for (int i = 0; i < firstHash.Length; i++)
            {
                if (firstHash[i] != secondHash[i])
                    return false;
            }
            return true;
        }





        public async void checkUpdate()
        {
            try
            {
                File.AppendAllText(directory + "\\ETW.log", "Checking updates...\n");
                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                File.Delete(directory + "\\server-rules.xml");
                HttpResponseMessage response = await client.GetAsync("http://" + server_ip + "/rules.xml");
                if (response.IsSuccessStatusCode)
                {
                    System.Net.Http.HttpContent content = response.Content;
                    var contentStream = await content.ReadAsStreamAsync();
                    using (var fs = new FileStream(directory + "\\server-rules.xml", FileMode.CreateNew))
                    {
                        await contentStream.CopyToAsync(fs).ConfigureAwait(false);
                        await contentStream.FlushAsync().ConfigureAwait(false);
                        await fs.FlushAsync().ConfigureAwait(false);
                    }
                    Thread.Sleep(100);
                }
                FileInfo local_rules = new FileInfo(@directory + "\\rules.xml");
                FileInfo server_rules = new FileInfo(@directory + "\\server-rules.xml");

                if (!FilesAreEqual_Hash(local_rules, server_rules))
                {
                    // UPDATE RULES FILE : stop and restart ETW capture
                    this.th.Abort();
                    this.th.Join();
                    Thread.Sleep(1000);
                    System.GC.Collect();
                    System.GC.WaitForPendingFinalizers();
                    File.Delete(directory + "\\rules.xml");
                    File.Move(directory + "\\server-rules.xml", directory + "\\rules.xml");
                    Alert("Rules have been updated.", 0);
                    this.th = new Thread(Monitor);
                    this.th.Priority = ThreadPriority.Lowest;
                    this.th.IsBackground = true;
                    this.th.Start();
                }
            }
            catch (Exception e)
            {
                File.AppendAllText(directory + "\\ETW.log", "Error while trying to update : " + e.ToString() + "\n");
            }
        }






        protected override void OnStart(string[] args)
        {
            string service_name = "ETWMonitor Agent";
            string imagepath = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + service_name, "ImagePath", string.Empty).ToString();
            int imagepath_length = imagepath.ToString().LastIndexOf("\\");
            this.directory = imagepath.ToString().Substring(0, imagepath_length).Trim();

            // get config from settings.conf
            while (this.token == "" || this.server_ip == "")
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
                    this.token = token;
                    this.server_ip = server_ip;
                }
                catch (Exception e)
                {
                    File.AppendAllText(directory + "\\ETW.log", "Error while trying to get settings config file : " + e.ToString() + "\n");
                }
                // retry in 10 seconds
                Thread.Sleep(10000);
            }


            this.th = new Thread(Monitor);
            this.th.Priority = ThreadPriority.Lowest;
            this.th.IsBackground = true;
            this.th.Start();

            // initial check update
            checkUpdate();


            updateTimer = new System.Timers.Timer();
            updateTimer.Elapsed += (sender, e) =>
            {
                checkUpdate();
            };
            updateTimer.Interval = 600000; // in milliseconds = 10 min
            updateTimer.Start();

            
        }


        protected override void OnStop()
        {
            Alert("ETWMonitor was stopped.", 0);
        }
    }
}
