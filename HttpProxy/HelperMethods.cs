using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;


namespace HttpProxy
{
  public class HelperMethods
  {

    #region MEMBERS

    private static HelperMethods inst;

    #endregion


    #region PROPERTIES

    public static HelperMethods Inst { get { return inst ?? (inst = new HelperMethods()); } }

    #endregion 


    #region PUBLIC

    public string GenerateCertificate(string hostname)
    {
      var certPath = HttpReverseProxy.HttpsReverseProxy.Server.DetermineCertificatePath(hostname);
      if (File.Exists(certPath))
      {
        return certPath;
      }

      HttpReverseProxy.HttpsReverseProxy.Server.CreateCertificate(hostname);
      if (File.Exists(certPath) == false)
      {
        new FileNotFoundException($"Certificate file for hostname {hostname} was not found.");
      }

      return certPath;
    }


    public void RemoveCertificateFile(string hostname)
    {
      var certPath = HttpReverseProxy.HttpsReverseProxy.Server.DetermineCertificatePath(hostname);
      if (File.Exists(certPath))
      {
        try
        {
          File.Delete(certPath);
        }
        catch (Exception ex)
        {
          Console.WriteLine($"Error occurred while deleting file {certPath}: {ex.Message}");
        }
      }
    }


    private System.Threading.Tasks.Task proxyTask;
    public void StartProxyServers(string certificatePath)
    {
      HttpReverseProxy.Config.LocalHttpServerPort = Config.LocalHttpPort;
      HttpReverseProxy.Config.LocalHttpsServerPort = Config.LocalHttpsPort;
      HttpReverseProxy.Config.CertificatePath = certificatePath;

      this.proxyTask = System.Threading.Tasks.Task.Run(() => { HttpReverseProxy.Program.StartProxyServer(); });
    }


    public void StopProxyServers()
    {
      HttpReverseProxy.HttpReverseProxy.Server.Stop();
      HttpReverseProxy.HttpsReverseProxy.Server.Stop();
    }


    public void RemoveFile(string path)
    {
      if (File.Exists(path))
      {
        try
        {
          File.Delete(path);
        }
        catch (Exception ex)
        {
          Console.WriteLine($"TestClean(EXC): {ex.Message}");
        }
      }
    }


    public string SendGet(string schema, string remoteHost, int remotePort, string path, string host)
    {
      var responseData = string.Empty;
      var url = $"{schema}://{remoteHost}:{remotePort}{path}";
      Console.WriteLine($"remoteHost: |{remoteHost}|");
      Console.WriteLine($"remotePort: |{remotePort}|");
      Console.WriteLine($"path: |{path}|");
      Console.WriteLine($"url: |{url}|");
      HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);

      request.Host = host;

      using (HttpWebResponse response = (HttpWebResponse) request.GetResponse())
      using (Stream stream = response.GetResponseStream())
      using (StreamReader reader = new StreamReader(stream))
      {
          responseData = reader.ReadToEnd();
      }

      return responseData;
    }


    public string SendRawGET(string schema, string remoteHost, int remotePort, string path, List<string> headers)
    {
      var retVal = string.Empty;
      var newLine = Environment.NewLine;
      var headersStr = string.Join(newLine, headers);
      var requestStr = $"GET {path} HTTP/1.1{newLine}{headersStr}{newLine}{newLine}";
      
      TcpClient client = new TcpClient(remoteHost, remotePort);
      NetworkStream stream = client.GetStream();
      byte[] send = Encoding.ASCII.GetBytes(requestStr);
      stream.Write(send, 0, send.Length);
      byte[] bytes = new byte[client.ReceiveBufferSize];
      var count = 1;
      var data = string.Empty;
      while ((count = stream.Read(bytes, 0, (int)client.ReceiveBufferSize)) > 0)
      {
        var dataStr = Encoding.ASCII.GetString(bytes, 0, count);
        data += dataStr;
      }
;
      stream.Close();
      client.Close();

      return data;
    }

    #endregion

  }
}
