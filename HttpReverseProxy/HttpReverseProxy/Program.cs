namespace HttpReverseProxy
{
  using HttpReverseProxy.Lib;
  using NConsoler;
  using System;

  public class Program
  {

    #region PUBLIC METHODS

    /// <summary>
    ///
    /// </summary>
    /// <param name="args"></param>
    public static void Main(string[] args)
    {
      Console.Clear();
      Console.WriteLine("HttpReverseProxy 0.9 (www.buglist.io)");
      Console.WriteLine("-------------------------------------\n\n");

      Initialize();
      Consolery.Run(typeof(Program), args);
    }


    /// <summary>
    ///
    /// </summary>
    public static void Initialize()
    {
      // Initialize program
      Config.LocalIp = Common.GetLocalIPAddress();
    }


    /*
     * HTTPReverseProxyServer.exe 80 /ru:www.test.ch/www/adsf /d
     * HTTPReverseProxyServer.exe 80 /rhp:www.blick.ch;80 /d
     */
    [Action]
    public static void StartServer(
            [Required(Description = "Local port")] string localPortParam,
            [Optional("", "c", Description = "")] string configurationFileParam,
            [Optional(false, "d")] bool debugParam,
            [Optional("", "p", Description = "")] string outputNamedPipeParam)
    {
      try
      {
        Config.LocalServerPort = int.Parse(localPortParam);
      }
      catch (Exception ex)
      {
        Console.WriteLine("Exception : {0}", ex.Message);
        return;
      }

      // Start proxy cRemoteSocket
      try
      {
        if (ProxyServer.Server.Start())
        {
          Console.WriteLine("Press enter to exit");
          Console.ReadLine();
          ProxyServer.Server.Stop();
        }
        else
        {
          Console.WriteLine("Something went wrong");
        }
      }
      catch (Exception ex)
      {
        Console.WriteLine("Something went wrong : {0}", ex.ToString());
      }
    }

    #endregion

  }
}