namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{
  public class PluginConfig
  {

    #region MEMBERS

    private static string configurationFileFullPath = string.Empty;
    private static bool ignoreHsts = true;

    #endregion

    #region PROPERTIES

    public static string ConfigurationFileFullPath { get { return configurationFileFullPath; } set { configurationFileFullPath = value; } }
    public static bool IgnoreHSTS { get { return ignoreHsts; } set { ignoreHsts = value; } }

    #endregion

  }
}
