namespace HttpReverseProxy.Plugin.Inject
{
  using HttpReverseProxyLib;

  public partial class Inject
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("Inject", Logging.Level.DEBUG, "Inject.OnUnload(): ");
    }
  }
}
