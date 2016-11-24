namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib;

  public partial class Weaken
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("Weaken", Logging.Level.DEBUG, "Weaken.OnUnload(): ");
    }
  }
}
