namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{
  public class PluginConfig
  {

    #region PROPERTIES

    public static string ConfigurationFileFullPath { get; set; } = string.Empty;

    public static bool IgnoreHsts { get; set; } = true;

    #endregion

  }
}
