namespace HttpReverseProxy.Plugin.Weaken
{

  public class Config
  {

    #region PROPERTIES

    public static string PluginName { get; private set; } = "Weaken";

    public static int PluginPriority { get; private set; } = 8;

    public static string PluginVersion { get; private set; } = "0.1";

    #endregion

  }
}