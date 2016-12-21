namespace HttpReverseProxy
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Interface;
  using System.Collections.Generic;


  public class Config
  {

    #region MEMBERS

    private static string localIp = string.Empty;
private static string defaultRemoteHost = "www.buglist.io";
    private static string remoteHostIp = string.Empty;
    private static int remoteHostPort = 80;
    private static int localHttpServerPort = 80;
    private static int localHttpsServerPort = 443;
    private static string certificatePath = string.Empty;
    private static string httpServer = "Apache";
    private static int maxSniffedClientDataSize = 4096;
    private static List<IPlugin> loadedPlugins = new List<IPlugin>();
    private static Loglevel loglevel;

    #endregion


    #region PROPERTIES

    public static string LocalIp { get { return localIp; } set { localIp = value; } }

    public static string DefaultRemoteHost { get { return defaultRemoteHost; } set { defaultRemoteHost = value; } }

    public static string RemoteHostIp { get { return remoteHostIp; } set { remoteHostIp = value; } }

    public static int RemoteHostPort { get { return remoteHostPort; } set { remoteHostPort = value; } }

    public static int LocalHttpServerPort { get { return localHttpServerPort; } set { localHttpServerPort = value; } }

    public static int LocalHttpsServerPort { get { return localHttpsServerPort; } set { localHttpsServerPort = value; } }

    public static string CertificatePath { get { return certificatePath; } set { certificatePath = value; } }

    public static string Server { get { return httpServer; } set { httpServer = value; } }

    public static List<IPlugin> LoadedPlugins { get { return loadedPlugins; } set { } }

    public static int MaxSniffedClientDataSize { get { return maxSniffedClientDataSize; } set { maxSniffedClientDataSize = value; } }

    public static Loglevel Loglevel { get { return loglevel; } set { loglevel = value; } }

    #endregion


    #region PUBLIC

    public static void AddNewPlugin(IPlugin newPlugin)
    {
      if (newPlugin != null &&
         loadedPlugins.FindAll(elem => elem.Config.Name == newPlugin.Config.Name).Count <= 0)
      {
        loadedPlugins.Add(newPlugin);
        loadedPlugins.Sort((s1, s2) => s1.CompareTo(s2));
      }
    }

    #endregion

  }
}
