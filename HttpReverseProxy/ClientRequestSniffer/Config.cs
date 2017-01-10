namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{

  public class Config
  {

    #region MEMBERS

    private static string pluginName = "ClientRequestSniffer";
    private static int pluginPriority = 9;
    private static string pluginVersion = "0.1";

    public static readonly int SERVER_RESPONSE_TIMEOUT = 10000;
    public static readonly string DATA_OUTPUT_PIPE_NAME = "Minary";

    #endregion


    #region PROPERTIES

    public static string PluginName { get { return pluginName; } set { } }

    public static int PluginPriority { get { return pluginPriority; } set { } }

    public static string PluginVersion { get { return pluginVersion; } set { } }

    #endregion

  }
}