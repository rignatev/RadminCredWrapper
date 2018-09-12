using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.Net;
using System.Reflection;

namespace RadminCredWrapper
{
    class Program
    {
        private static Version version = Assembly.GetExecutingAssembly().GetName().Version;
        public static string Title = $"{Assembly.GetExecutingAssembly().GetName().Name} v{version.Major}.{version.Minor}";
        #region string constants
        private const string msgBadArgs = "The command line arguments are improperly formed.\nUse /help for show available commands";
        private const string msgHelp = @"
Author: Ignatyev Roman
URL: https://github.com/rignatev/RadminCredWrapper

Syntaxis:
>RadminCredWrapper.exe = [[/radminfile:{radmin_path}] /args:{radmin_args} /credname:{name}] | [/? | /help | /add:{name} | /remove:{name} | /clear | /list | /export:{passphrase} | /import:{passphrase}]

Groupped arguments:
    /radminfile:{radmin_path} - {radmin_path} is a full or relative path to the radmin.exe;
    /args:{radmin_args} - {radmin_args} are radmin command line arguments;
    /credname:{name} - {name} is a name for stored credentials.

Single arguments:
    /?, /help - show current help;
    /add:{name} - add a new credential with the {name} to a storage. Ask user credential window will be shown;
    /remove:{name} - remove a credential with the {name} from a storage;
    /clear - remove all radmin credentials from a storage;
    /list - show names of stored credentials;
    /export:{passphrase} - export all credentials from a storage to the file encrypted with the {passphrase}. Save file dialog window will be shown;
    /import:{passphrase} - import all credentials from the file to the storage encrypted with the {passphrase}. Open file dialog window will be shown.

Notes: If an argument value contains spaces, surround it by double quotes.

Example 1:
Note: Add a new credential with the name 'CRED1' to a storage
>RadminCredWrapper.exe /add:CRED1

Example 2:
Note: Launch Radmin using credential stored with name 'CRED1' and Radmin command line arguments
>RadminCredWrapper.exe /radminfile:""..\Tools\Radmin\radmin.exe"" /connect:""10.10.1.123 /noinput"" /credname:CRED1

Example 3:
Note: Export all credentials to a file
>RadminCredWrapper.exe /export:""MySuperPassword""
";
        #endregion string constants

        [STAThreadAttribute]
        static int Main(string[] args)
        {
            string radminFilePath = "Radmin.exe";
            string[] singleArgs = { "?", "help", "add", "remove", "clear", "list", "export", "import" };
            string[] groupArgs = { "radminfile", "args", "credname", "waitsec" };
            int waitSec = 5;

            try
            {
                Dictionary<string, string> commandLineArgs = ParseArgs(args);

                if (commandLineArgs == null)
                {
                    MessageBox.Show(msgBadArgs, Title);
                    return 1;
                }

                if (commandLineArgs.Keys.Count == 0)
                {
                    if (File.Exists(radminFilePath))
                    {
                        LaunchRadmin(radminFilePath, null);
                    }
                    else
                    {
                        ShowHelp();
                    }
                    return 0;
                }

                // Processing single argument
                if (commandLineArgs.Keys.Count == 1)
                {
                    bool wrongArgsUsage = false;
                    switch (commandLineArgs.Keys.ElementAt(0))
                    {
                        case "add":
                            if (commandLineArgs["add"] == null)
                            {
                                MessageBox.Show($"Missed a name of credential at parameter '/add'. Now exiting...", Title);
                                return 1;
                            }
                            if (!RadminCredentialsHelper.Add(commandLineArgs["add"]))
                            {
                                MessageBox.Show($"Credential named '{commandLineArgs["add"]}' have not been added", Title);
                                return 1;
                            }
                            MessageBox.Show($"Credential named '{commandLineArgs["add"]}' have been successfully added", Title);
                            break;
                        case "remove":
                            if (commandLineArgs["remove"] == null)
                            {
                                MessageBox.Show($"Missed a name of credential at parameter '/remove'. Now exiting...", Title);
                                return 1;
                            }
                            if (!RadminCredentialsHelper.Remove(commandLineArgs["remove"]))
                            {
                                MessageBox.Show($"Credential named '{commandLineArgs["remove"]}' have not been removed", Title);
                                return 1;
                            }
                            MessageBox.Show($"Credential named '{commandLineArgs["remove"]}' have been successfully removed", Title);
                            break;
                        case "clear":
                            if (commandLineArgs["clear"] != null)
                            {
                                wrongArgsUsage = true;
                                break;
                            }
                            RadminCredentialsHelper.Clear();
                            break;
                        case "list":
                            if (commandLineArgs["list"] != null)
                            {
                                wrongArgsUsage = true;
                                break;
                            }
                            RadminCredentialsHelper.List();
                            break;
                        case "export":
                            if (commandLineArgs["export"] == null)
                            {
                                MessageBox.Show($"Missed a passphrase at parameter '/export'. Now exiting...", Title);
                                return 1;
                            }
                            RadminCredentialsHelper.Export(commandLineArgs["export"]);
                            break;
                        case "import":
                            if (commandLineArgs["import"] == null)
                            {
                                MessageBox.Show($"Missed a passphrase at parameter '/import'. Now exiting...", Title);
                                return 1;
                            }
                            RadminCredentialsHelper.Import(commandLineArgs["import"]);
                            break;
                        case "?":
                            ShowHelp();
                            break;
                        case "help":
                            ShowHelp();
                            break;
                        default:
                            wrongArgsUsage = true;
                            break;
                    }
                    if (wrongArgsUsage == true)
                    {
                        MessageBox.Show(msgBadArgs, Title);
                        return 1;
                    }

                    return 0;
                }

                // Processing grouped arguments
                // Validating grouped argumetns
                foreach (var argName in commandLineArgs.Keys)
                {
                    if (!groupArgs.Contains(argName))
                    {
                        MessageBox.Show(msgBadArgs, Title);
                        return 1;
                    }
                }

                // Validating 'radminfile' argument
                if (commandLineArgs.ContainsKey("radminfile"))
                {
                    radminFilePath = commandLineArgs["radminfile"];
                }

                // Validating radmin executable file existance
                if (!File.Exists(radminFilePath))
                {
                    radminFilePath = AppDomain.CurrentDomain.BaseDirectory + radminFilePath;
                    if (!File.Exists(radminFilePath))
                    {
                        MessageBox.Show($"Radmin executable file not found. Now exiting...\nPath:{commandLineArgs["radminfile"]}", Title);
                        return 1;
                    }
                }

                string radminArgs = String.Empty;
                NetworkCredential networkCredential = null;

                // Validating 'args' and 'credname' arguments
                if (commandLineArgs.ContainsKey("args"))
                {
                    if (!commandLineArgs["args"].Contains("/connect:"))
                    {
                        MessageBox.Show($"Radmin args not contains the connection argument. Now exiting...", Title);
                        return 1;
                    }

                    radminArgs = commandLineArgs["args"];

                    if (commandLineArgs.ContainsKey("credname"))
                    {
                        if (commandLineArgs["credname"] == null)
                        {
                            MessageBox.Show($"Missed a name of credential at parameter '/credname'. Now exiting...", Title);
                            return 1;
                        }
                        networkCredential = RadminCredentialsHelper.Get(commandLineArgs["credname"]);
                        if (networkCredential == null)
                        {
                            MessageBox.Show($"Credential with a name {commandLineArgs["credname"]} not found", Title);
                        }
                    }
                }

                // Validating 'waitsec' argument
                if (commandLineArgs.ContainsKey("waitsec"))
                {
                    waitSec = Convert.ToInt32(commandLineArgs["waitsec"]);
                }

                // Launching Radmin
                LaunchRadmin(radminFilePath, radminArgs);

                // Getting the host name from 'args' and forming the connection window title
                string caption = null;
                string patternHost = @"^/connect:(?<host>\S+)";
                var match = Regex.Match(radminArgs, patternHost);

                if (match.Success)
                {
                    string host = match.Groups["host"].Value.Contains(':') ? match.Groups["host"].Value.Split(':')[0] : match.Groups["host"].Value;
                    caption = $"Система безопасности Radmin: {host}";
                }

                // Filling the connection form if all necesary data exists
                if (args != null && networkCredential != null && caption != null)
                {
                    SendRadminCredentials(caption, networkCredential, waitSec);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"The application caused an error\nError message:\n{ex.Message}\nSource:\n{ex.Source}\nStackTrace:\n{ex.StackTrace}", Title);
                return 1;
            }

            return 0;
        }

        private static void LaunchRadmin(string path, string args)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.UseShellExecute = false;
            psi.FileName = path;
            if (!String.IsNullOrEmpty(args))
            {
                psi.Arguments = args;
            }

            Process radminProcess = new Process();
            radminProcess.StartInfo = psi;
            radminProcess.Start();

            while (radminProcess.Handle == IntPtr.Zero)
            {
                System.Threading.Thread.Sleep(50);
            }
        }

        private static IntPtr FindWindow(string caption, int waitSec)
        {
            int counter = 0;
            waitSec *= 20;
            IntPtr hWnd = IntPtr.Zero;

            while (counter <= waitSec && hWnd == IntPtr.Zero)
            {
                hWnd = NativeCode.FindWindow(null, caption);
                counter++;
                System.Threading.Thread.Sleep(50);
            }

            return hWnd;
        }

        private static void SendRadminCredentials(string caption, NetworkCredential credential, int waitSec)
        {
            IntPtr mainWindowHandler = FindWindow(caption, waitSec);
            if (mainWindowHandler != IntPtr.Zero)
            {
                IntPtr radminEditBox1 = NativeCode.FindWindowEx(mainWindowHandler, IntPtr.Zero, "Edit", null);
                NativeCode.SendMessage(radminEditBox1, NativeCode.WM_SETTEXT, 0, credential.UserName);
                IntPtr radminEditBox2 = NativeCode.FindWindowEx(mainWindowHandler, radminEditBox1, "Edit", null);
                NativeCode.SendMessage(radminEditBox2, NativeCode.WM_SETTEXT, 0, credential.Password);
                IntPtr radminButton1 = NativeCode.FindWindowEx(mainWindowHandler, radminEditBox2, "Button", null);
                IntPtr radminButton2 = NativeCode.FindWindowEx(mainWindowHandler, radminButton1, "Button", null);
                NativeCode.SendMessage(radminButton2, NativeCode.BM_CLICK, 0, null);
            }
            else
            {
                MessageBox.Show($"Cannot find the Radmin connection window.", Title);
            }
        }

        private static void ShowHelp()
        {
            MessageBox.Show(msgHelp, Title);
        }

        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            Dictionary<string, string> parsedArgs = new Dictionary<string, string>();
            string patternKeyValue = @"^/(?<argname>\w+):(?<argvalue>.+$)";
            string patternSwitch = @"^/(?<switch>(\w+$|\?))";

            if (args.Length != 0)
            {
                foreach (var arg in args)
                {
                    var match = Regex.Match(arg, patternKeyValue);
                    if (match.Success)
                    {
                        parsedArgs.Add(match.Groups["argname"].Value.ToLower(), match.Groups["argvalue"].Value);
                        continue;
                    }

                    match = Regex.Match(arg, patternSwitch);
                    if (match.Success)
                    {
                        parsedArgs.Add(match.Groups["switch"].Value.ToLower(), null);
                        continue;
                    }

                    return null;
                }
            }

            return parsedArgs;
        }
    }
}
