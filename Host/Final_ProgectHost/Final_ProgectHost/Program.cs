using System;
using System.Text;
using Intel.Dal;
using System.Collections.Generic;
using System.Linq;
using System.IO;

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;



namespace Final_ProgectHost
{

    class Program
    {
       
        static void Main(string[] args)
        {
#if AMULET
            Jhi.DisableDllValidation = true;
#endif
            Jhi jhi = Jhi.Instance;
            JhiSession session;

            
            string appletID = "052fd314-a269-4b83-9b97-5cf9f1df21b7";
            string appletPath = "C:\\workspaces\\Final_Progect\\bin\\Final_Progect-debug.dalp";

            // Install the Trusted Application
            Console.WriteLine("Installing the applet.");
            jhi.Install(appletID, appletPath);

            // Start a session with the Trusted Application
            byte[] initBuffer = new byte[] { }; // Data to send to the applet onInit function
            Console.WriteLine("Opening a session.");
            jhi.CreateSession(appletID, JHI_SESSION_FLAGS.None, initBuffer, out session);



            // Step 1: Generate a new asymmetric key pair
            RSACryptoServiceProvider serverRsa = new RSACryptoServiceProvider();
            // Step 2: Receive the client's public key and store it for later use
            RSACryptoServiceProvider clientRsa = new RSACryptoServiceProvider();

            // Step 3: Create a TcpListener to listen for incoming connections
            TcpListener listener = new TcpListener(IPAddress.Any, 8888);
            listener.Start();
            Console.WriteLine("start listening");

            // Step 4: Accept incoming connections and establish a connection with the client
            TcpClient client = listener.AcceptTcpClient();
            Console.WriteLine("client connected");

            //ns is the socket to pass data among the server and the client
            NetworkStream ns = client.GetStream();
            getAndSendPublicKeys();
            Console.WriteLine("function of publicKeys finished");

            // Step 5: Receive encrypted data from the client and decrypt it using the server's private key
            int MAXINFOSIZE = 128;
            byte[] encryptedMassage = new byte[MAXINFOSIZE];
            int comm;
            do
            {
                ns.Read(encryptedMassage, 0, MAXINFOSIZE);
                Console.WriteLine("encripted data was recieved from the client");

                byte[] decryptedResponse = serverRsa.Decrypt(encryptedMassage, false);
                int bytesRead = decryptedResponse.Length;
                string response = Encoding.UTF8.GetString(decryptedResponse, 2, bytesRead - 2);
                byte command = decryptedResponse[0];
                byte personID = decryptedResponse[1];
                comm = Convert.ToInt32(command);

                if (comm == 2)
                {
                    Console.WriteLine("the client asked to save data");
                    byte[] encriptedByAplet = encriptDataByAplet(decryptedResponse);
                    Console.WriteLine("the data was encripted by aplet");
                    saveInFile(encriptedByAplet, personID);
                    Console.WriteLine("the data was written to the customer's file");
                    byte[] OKresponse = UTF32Encoding.UTF8.GetBytes("ok");
                    byte[] encriptedDataASinc = clientRsa.Encrypt(OKresponse, false);
                    ns.Write(encriptedDataASinc, 0, encriptedDataASinc.Length);
                }
                else if (comm == 3)
                {
                    Console.WriteLine("the client asked to get his data");
                    byte[] dataFromFile = getFromFile(personID);
                    Console.WriteLine("the data was taken from the file");
                    byte[] decriptedByAplet = decriptDataByAplet(dataFromFile);
                    Console.WriteLine("the data was decripted by aplet");
                    //send to client
                    byte[] encriptedDataASinc = clientRsa.Encrypt(decriptedByAplet, false);
                    ns.Write(encriptedDataASinc, 0, encriptedDataASinc.Length);
                    Console.WriteLine("data was sent to client");

                }

            } while (comm!=0);

            Console.WriteLine("the client ask to disconnect");
            byte[] closeResponse = UTF32Encoding.UTF8.GetBytes("close connection");
            byte[] encriptedDataAClose = clientRsa.Encrypt(closeResponse, false);
            ns.Write(encriptedDataAClose, 0, encriptedDataAClose.Length);


            // Close the session
            Console.WriteLine("Closing the session.");
            jhi.CloseSession(session);

            //Uninstall the Trusted Application
            Console.WriteLine("Uninstalling the applet.");
            jhi.Uninstall(appletID);
           
            Console.WriteLine("Press Enter to finish.");
            Console.Read();




    //functions
            //read data from file
            byte[] getFromFile(byte pId)
            {
                int PID = Convert.ToInt32(pId);
                String fileName = "peoplesDiseases" + PID + ".txt";
                String path = "C:\\workspaces\\filesOfFinalProjectHost\\" + fileName;
                byte[] readText = File.ReadAllBytes(path);
                Console.WriteLine("read the information from the customer's file");
                return readText;
            }
            //save data in file
            void saveInFile(byte[] data, byte pID)
            {
                int PID = Convert.ToInt32(pID);
                //the document is in repos in bin in amulet
                String fileName = "peoplesDiseases" + PID + ".txt";
                String path = "C:\\workspaces\\filesOfFinalProjectHost\\"+fileName;
                if (File.Exists(path))
                    using (BinaryWriter binWriter = new BinaryWriter(File.Open(path, FileMode.Append)))
                    {
                        //writes the data to the stream
                        //write only the data without commandID and personID
                        binWriter.Write(data,0,data.Length);

                    }
                else
                {
                    using (BinaryWriter binWriter = new BinaryWriter(File.Open(path, FileMode.Create)))
                    {
                        //writes the data to the stream
                        //write only the data without commandID and personID
                        binWriter.Write(data, 0, data.Length);

                    }
                }
            }

            byte[] decriptDataByAplet(byte[] data2Decript)
            {
                byte[] sendBuff = new byte[16];
                byte[] recvBuff = new byte[2000]; // A buffer to hold the output data from the TA
                //Buffer.BlockCopy(data2Decript, 0, sendBuff, 0, data2Decript.Length);

                int cmdId = 2; // The ID of the command to be performed by the TA 
                int responseCode;
                jhi.SendAndRecv2(session, cmdId, data2Decript, ref recvBuff, out responseCode);
                Console.WriteLine("decript the data by aplet");
                Console.Out.WriteLine("the aplet response is " + UTF32Encoding.UTF8.GetString(recvBuff));
                return recvBuff;
            }
            // Send and Receive data to/from the Trusted Application
            byte[] encriptDataByAplet(byte[] data2Encript)
            {
                byte[] sendBuff = new byte[1000];
                byte[] recvBuff = new byte[2000]; // A buffer to hold the output data from the TA
                Buffer.BlockCopy(data2Encript, 2, sendBuff, 0, data2Encript.Length-2);
                
                int cmdId = 1; // The ID of the command to be performed by the TA 
                int responseCode;
                jhi.SendAndRecv2(session, cmdId, sendBuff, ref recvBuff, out responseCode);
                Console.WriteLine("encript the data by aplet"); 
                Console.Out.WriteLine("the aplet response is " + UTF32Encoding.UTF8.GetString(recvBuff));
                return recvBuff;
            }

            //get the public key of the client and send him the server's public key
            void getAndSendPublicKeys()
            {
                int PUBLICKEYSIZE = 131;
                int EXPONENTSIZE = 3;  
                int MODULESIZE = 128;

                byte[] recvbuffstream = new byte[PUBLICKEYSIZE];
                ns.Read(recvbuffstream, 0, PUBLICKEYSIZE);
                RSAParameters resP = new RSAParameters();
                //divide recvbuffstream to publicKey and exponent of client
                byte[] publicKeyM = new byte[MODULESIZE];
                byte[] exponentE = new byte[EXPONENTSIZE];
                Buffer.BlockCopy(recvbuffstream, 0, publicKeyM, 0, MODULESIZE);
                Buffer.BlockCopy(recvbuffstream, MODULESIZE, exponentE, 0, EXPONENTSIZE);
                resP.Modulus = publicKeyM;
                resP.Exponent = exponentE;
                clientRsa.ImportParameters(resP);
                Console.WriteLine("client's public keys were recieved");


                //send my keys to other side
                RSAParameters tmp = serverRsa.ExportParameters(false);
                //to send module and e to the server
                byte[] publicKeyBytes = new byte[PUBLICKEYSIZE];
                Buffer.BlockCopy(tmp.Modulus, 0, publicKeyBytes, 0, MODULESIZE);
                Buffer.BlockCopy(tmp.Exponent, 0, publicKeyBytes, MODULESIZE, EXPONENTSIZE);
                ns.Write(publicKeyBytes, 0, publicKeyBytes.Length);
                Console.WriteLine("my public keys were sent");
            }

        }

    }
    
}