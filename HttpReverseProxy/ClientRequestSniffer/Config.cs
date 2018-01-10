namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{

  public class Config
  {

    #region MEMBERS

    public static readonly int SERVER_RESPONSE_TIMEOUT = 10000;
    public static readonly string DATA_OUTPUT_PIPE_NAME = "Minary";

    #endregion


    #region PROPERTIES

    public static string PluginName { get; private set; } = "ClientRequestSniffer";

    public static int PluginPriority { get; private set; } = 9;

    public static string PluginVersion { get; private set; } = "0.1";

    #endregion

  }
}