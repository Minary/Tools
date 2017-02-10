namespace HttpReverseProxy
{
  using Fclp;
  using global::HttpReverseProxy.Http;
  using global::HttpReverseProxy.Https;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.IO;
  using System.Net.NetworkInformation;
  using System.Text.RegularExpressions;
  using System.Security.Cryptography.X509Certificates;


  public class Program
  {

    #region PUBLIC METHODS

    /// <summary>
    ///
    /// </summary>
    /// <param name="args"></param>
    public static void Main(string[] args)
    {
      string certificateHost = string.Empty;
      var parser = new FluentCommandLineParser();
      parser.IsCaseSensitive = false;

      parser.Setup<string>("createCertificate")
       .Callback(item => { certificateHost = item; })
       .WithDescription("Create selfsigned certificate for HOSTNAME");

      parser.Setup<int>("httpPort")
       .Callback(item => { Config.LocalHttpServerPort = item; })
       .SetDefault(80)
       .WithDescription("Define TCP port for incoming HTTP requests. Default port is \"80\"");

      parser.Setup<int>("httpsPort")
       .Callback(item => { Config.LocalHttpsServerPort = item; })
       .SetDefault(443)
       .WithDescription("Define TCP port for incoming HTTPS requests. Default port is \"443\"");

      parser.Setup<string>("certificate")
       .Callback(item => { Config.CertificatePath = item; })
       .WithDescription("Define certificate file path");

      parser.Setup<Loglevel>("loglevel")
       .Callback(item => Config.Loglevel = item)
       .SetDefault(Loglevel.Info)
       .WithDescription("Define log level. Default level is \"Info\". Possible values are: " + string.Join(", ", Enum.GetNames(typeof(Loglevel))));

      // sets up the parser to execute the callback when -? or --help is detected
      parser.SetupHelp("?", "help")
            .UseForEmptyArgs()
            .Callback(text => Console.WriteLine(text));

      ICommandLineParserResult result = parser.Parse(args);
      if (result.HasErrors == true)
      {
        Console.WriteLine("{0}\r\n\r\n", result.ErrorText);
      }
      else if (!string.IsNullOrEmpty(certificateHost) && !string.IsNullOrWhiteSpace(certificateHost))
      {
        CreateCertificate(certificateHost);
      }
      else if (string.IsNullOrEmpty(Config.CertificatePath))
      {
        Console.WriteLine("You did not define a certificate file");
      }
      else
      {
        StartProxyServer();
      }
    }


    private static void CreateCertificate(string certificateHost)
    {
      HttpsReverseProxy.Server.CreateCertificate(certificateHost);
    }


    private static void StartProxyServer()
    {
      Config.LocalIp = Lib.Common.GetLocalIpAddress();
      HttpReverseProxyLib.Logging.Instance.LoggingLevel = Config.Loglevel;

      // Parse HTTP port parameter
      try
      {
        if (IsPortAvailable(Config.LocalHttpServerPort) == false)
        {
          Console.WriteLine("The HTTP port ({0}) is used by another proces", Config.LocalHttpServerPort);
          return;
        }

        // Initialize TLS/SSL parameters for HTTPS connections
        if (IsPortAvailable(Config.LocalHttpsServerPort) == false)
        {
          Console.WriteLine("The HTTPS port ({0}) is used by another proces", Config.LocalHttpsServerPort);
          return;
        }

        // Check if certificate is valid
        if (VerifyCertificateValidity(Config.CertificatePath) == false)
        {
          Console.WriteLine("The certificate \"{0}\" is invalid", Config.CertificatePath);
          return;
        }
      }
      catch (Exception ex)
      {
        Console.WriteLine("Exception occurred: {0}", ex.Message);
        return;
      }

      // Start HTTP proxy server
      try
      {
        if (HttpReverseProxy.Server.Start(Config.LocalHttpServerPort) == false)
        {
          throw new Exception("HTTP reverse proxy server could be started");
        }

        if (HttpsReverseProxy.Server.Start(Config.LocalHttpsServerPort, Config.CertificatePath) == false)
        {
          throw new Exception("HTTPS reverse proxy server could be started");
        }

        Console.WriteLine("Press enter to exit");
        Console.ReadLine();
      }
      catch (Exception ex)
      {
        Console.WriteLine("Something went wrong: {0}", ex.ToString());
      }

      HttpReverseProxy.Server.Stop();
      HttpsReverseProxy.Server.Stop();
    }

    #endregion


    #region PRIVATE

    private static bool VerifyCertificateValidity(string certificateFilePath)
    {
      if (string.IsNullOrEmpty(certificateFilePath))
      {
        throw new Exception("The certificate file parameter is invalid");
      }

      if (!File.Exists(certificateFilePath))
      {
        throw new Exception("The certificate file does not exist");
      }

      X509Certificate2Collection collection = new X509Certificate2Collection();
      try
      {
        collection.Import(certificateFilePath, string.Empty, X509KeyStorageFlags.PersistKeySet);
      }
      catch (Exception ex)
      {
        throw new Exception(string.Format("The following error occurred while loading certificate file: {0}", ex.Message));
      }

      if (collection.Count < 1)
      {
        throw new Exception("No valid certificate data found");
      }

      if (collection.Count > 1)
      {
        throw new Exception("No valid certificate data found");
      }

      return true;
    }


    private static bool IsPortAvailable(int portNo)
    {
      if (portNo <= 0 || portNo > 65535)
      {
        throw new Exception("The port is invalid");
      }

      bool isPortAvailable = true;
      IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
      System.Net.IPEndPoint[] ipEndPoints = ipGlobalProperties.GetActiveTcpListeners();

      foreach (System.Net.IPEndPoint endPoint in ipEndPoints)
      {
        if (endPoint.Port == portNo)
        {
          isPortAvailable = false;
          break;
        }
      }

      return isPortAvailable;
    }

    #endregion

  }
}