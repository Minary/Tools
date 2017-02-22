namespace HttpReverseProxy.Plugin.Weaken
{


  public class Config
  {

    #region MEMBERS

    private static string pluginName = "Weaken";
    private static int pluginPriority = 8;
    private static string pluginVersion = "0.1";

    #endregion


    #region PROPERTIES

    public static string PluginName { get { return pluginName; } set { } }

    public static int PluginPriority { get { return pluginPriority; } set { } }

    public static string PluginVersion { get { return pluginVersion; } set { } }

    #endregion

  }
}