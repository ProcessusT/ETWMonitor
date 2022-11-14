using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.ServiceProcess;
using System.Timers;
using System.Threading;
using System.Xml;
using System.Collections;
using System.Security.Cryptography;

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
        private static System.Timers.Timer updateTimer;
        public Thread th;
        public TraceEventSession session;


        public void Alert(string message, int level)
        {
            try
            {   
                if( this.token == "" || this.server_ip == "")
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
            }
            catch (Exception e)
            {
                File.AppendAllText(directory + "\\ETW.log", "Error while reading XML rules file : " + e.ToString()+"\n\n");
            }


            


            var existingSessions = TraceEventSession.GetActiveSessionNames();
            var sessionName = "ETWMonitor";
            using (this.session = new TraceEventSession(sessionName))
            {
                // For ETW providers list go to : https://github.com/repnz/etw-providers-docs
                foreach(string provider in providers_list)
                {
                    session.EnableProvider(new Guid(provider));
                }
                session.Source.Dynamic.All += delegate (TraceEvent data)
                {
                    /*FOR DEBUGGING
                    if (data.ToString().ToLower().Contains("ATTACKER IP")){
                        Console.WriteLine(data.ToString());
                    }*/


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
                                if (alert_msg.ToLower().Contains("\\n"))
                                {
                                    alert_msg.Replace("\\n", "\n");
                                }
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
                                    // catch username or ip address
                                    if(data.ToString().ToLower().Contains("clientip: "))
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
                                    if (data.ToString().ToLower().Contains("clientip=\""))
                                    {
                                        int client_name = data.ToString().IndexOf("ClientIP=\"") + 10;
                                        string ip_source = data.ToString().Substring(client_name);
                                        int client_name_length = ip_source.ToString().IndexOf(":");
                                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();
                                        alert_msg = alert_msg + "\nFrom : " + ip_source;
                                    }
                                    if (data.ToString().ToLower().Contains("address=\""))
                                    {
                                        int client_name = data.ToString().IndexOf("Address=\"") + 9;
                                        string ip_source = data.ToString().Substring(client_name);
                                        int client_name_length = ip_source.ToString().IndexOf(":");
                                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();
                                        alert_msg = alert_msg + "\nFrom : " + ip_source;
                                    }
                                    if (data.ToString().ToLower().Contains("username=\""))
                                    {
                                        int client_name = data.ToString().IndexOf("UserName=\"") + 10;
                                        string ip_source = data.ToString().Substring(client_name);
                                        int client_name_length = ip_source.ToString().IndexOf("\"");
                                        ip_source = ip_source.ToString().Substring(0, client_name_length).Trim();
                                        alert_msg = alert_msg + "\nUsername : " + ip_source;
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
                    this.session.Source.StopProcessing();
                    this.session.Stop();
                    this.session.Dispose();
                    this.th.Abort();
                    this.th.Join();
                    Thread.Sleep(1000);
                    System.GC.Collect();
                    System.GC.WaitForPendingFinalizers();
                    File.Delete(directory + "\\rules.xml");
                    File.Move(directory + "\\server-rules.xml", directory + "\\rules.xml");
                    Alert("Rules have been updated.", 0);
                    this.th = new Thread(Monitor);
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

            this.th = new Thread(Monitor);
            this.th.IsBackground = true;
            this.th.Start();

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
