namespace HttpReverseProxy
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System.Collections.Generic;


  public class Config
  {

    #region PROPERTIES

    public static string LocalIp { get; set; } = string.Empty;

    public static string DefaultRemoteHost { get; private set; } = "minary.io";

    public static string RemoteHostIp { get; set; } = string.Empty;

    public static int LocalHttpServerPort { get; set; } = 80;

    public static int LocalHttpsServerPort { get; set; } = 443;

    public static string CertificatePath { get; set; } = string.Empty;

    public static List<IPlugin> LoadedPlugins { get; set; } = new List<IPlugin>();

    public static int MaxSniffedClientDataSize { get; private set; } = 4096;

    public static Loglevel CurrentLoglevel { get; set; } = Loglevel.Info;

    #endregion


    #region PUBLIC

    public static void AddNewPlugin(IPlugin newPlugin)
    {
      if (newPlugin != null &&
          LoadedPlugins.FindAll(elem => elem.Config.Name == newPlugin.Config.Name).Count <= 0)
      {
        LoadedPlugins.Add(newPlugin);
        LoadedPlugins.Sort((s1, s2) => s1.CompareTo(s2));
      }
    }

    #endregion

  }
}
