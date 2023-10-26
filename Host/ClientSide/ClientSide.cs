using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

using System.Net.Sockets;
using System.Security.Authentication;

using System.Net.Security;
using System.Net;

namespace ClientSide
{
    class ClientSide
    {


        static void Main(string[] args)
        {
            bool actSucceed;
            // Step 1: Generate a new asymmetric key pair
            //assuming keys are generated automatically??????
            RSACryptoServiceProvider clientRsa = new RSACryptoServiceProvider();
            RSACryptoServiceProvider serverRsa = new RSACryptoServiceProvider();

            // Step 2: Create a TcpClient to connect to the server
            TcpClient client = new TcpClient();
            // Step 3: Establish a connection with the server
            client.Connect("127.0.0.1", 8888);
            Console.WriteLine("connected to the server");
            NetworkStream ns = client.GetStream();
            
            getAndSendPublicKeys();
            Console.WriteLine("function of publicKeys finished");

            actSucceed = saveInServer();    //sent to the server my diseases
            if (actSucceed)
                Console.WriteLine("function of saveInServer succeed");
            
            Console.WriteLine("I ask my information from the server");
            askFromServer(3);   //ask from server to get the my information
            
            Console.WriteLine("I ask to close the connection with the server");
            askFromServer(0);   //notify the server I want to disconnect

            return;




            //functions
            void getAndSendPublicKeys()
            {   
                //save keys of server
                int PUBLICKEYSIZE = 131;
                int EXPONENTSIZE = 3;
                int MODULESIZE = 128;

                //m=128 e=4 bytes

                // Step 4: Send the public key to the server
                RSAParameters tmp = clientRsa.ExportParameters(false);
                //to send module and e to the server
                byte[] publicKeyBytes = new byte[PUBLICKEYSIZE];
                Buffer.BlockCopy(tmp.Modulus, 0, publicKeyBytes, 0, MODULESIZE);
                Buffer.BlockCopy(tmp.Exponent, 0, publicKeyBytes, MODULESIZE, EXPONENTSIZE);
                ns.Write(publicKeyBytes, 0, publicKeyBytes.Length);
                Console.WriteLine("my public keys were sent");

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
                serverRsa.ImportParameters(resP);
                Console.WriteLine("server's public keys were recieved");
            }
            bool saveInServer()
            {
                // Step 5: Send a message to the server using its public key
                string diseases = "OCD\nADHD\nasthma\n";
                Console.WriteLine("My diseases: " + diseases);
                byte[] message = Encoding.ASCII.GetBytes(diseases);
                byte commandID = 2;
                byte personID = 5;//to change to get the pid from the console
                byte[] messagePlusComm = new byte[message.Length + 2];
                messagePlusComm[0] = commandID;
                messagePlusComm[1] = personID;
                Buffer.BlockCopy(message, 0, messagePlusComm, 2, message.Length);
                byte[] encryptedMessage = serverRsa.Encrypt(messagePlusComm, false);
                //no need to create new coonection. the server is already listening
                ns.Write(encryptedMessage, 0, encryptedMessage.Length);
                Console.WriteLine("My diseases were sent to the server");
                //// Step 6: Receive encrypted data from the server and decrypt it using the client's private key
                int MAXINFOSIZE = 128;//117;  //to chang to 128
                byte[] encryptedDataRecieved = new byte[MAXINFOSIZE];

                ns.Read(encryptedDataRecieved, 0, encryptedDataRecieved.Length);
               
                byte[] decryptedData = clientRsa.Decrypt(encryptedDataRecieved, false);//using private key that is maybe unknown outside. did not use function from microsoft because did not see what is special...
                int bytesRead = decryptedData.Length;
                string response = Encoding.UTF8.GetString(decryptedData, 0, bytesRead);
                Console.WriteLine("server response: " + response);
                if (response == "ok")
                    return true;
                return false;
            }
            void askFromServer(byte commandID)
            {
                // Step 5: Send a message to the server using its public key
                byte personID = 5;//to change to get the pid from the console
                byte[] messagePlusComm = new byte[2];
                messagePlusComm[0] = commandID;
                messagePlusComm[1] = personID;
                byte[] encryptedMessage = serverRsa.Encrypt(messagePlusComm, false);
                //no need to create new coonection. the server is already listening
                ns.Write(encryptedMessage, 0, encryptedMessage.Length);
                //// Step 6: Receive encrypted data from the server and decrypt it using the client's private key
                int MAXINFOSIZE = 128;//117;
                byte[] encryptedDataRecieved = new byte[MAXINFOSIZE];
                //must listen again so doesn't take old data. but no need for new listener
                //TcpClient listenForAnsInfo = listener.AcceptTcpClient();
                //NetworkStream nsListenForAnsInfo = listenForAnsInfo.GetStream();
                int bytesRead = encryptedDataRecieved.Length;
                ns.Read(encryptedDataRecieved, 0, encryptedDataRecieved.Length);
                byte[] decryptedData = clientRsa.Decrypt(encryptedDataRecieved, false);//using private key that is maybe unknown outside. did not use function from microsoft because did not see what is special...

                string response = Encoding.UTF8.GetString(decryptedData, 0, decryptedData.Length);
                Console.WriteLine("server response: "+response);

            }
        }


    }
}
