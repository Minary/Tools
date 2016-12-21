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
      Logging.Instance.LogMessage("Inject", Loglevel.DEBUG, "Inject.OnUnload(): ");
    }
  }
}
