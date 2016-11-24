namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.Exceptions;

  public partial class HostMapping
  {

    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <returns></returns>
    public PluginInstruction OnPostServerHeadersResponse(RequestObj requestObj)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      PluginInstruction ipPluginInstruction = this.ProcessServerResponseHeaders(requestObj);

      return ipPluginInstruction;
    }

    #endregion


    #region PRIVATE

    /// <summary>
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    public PluginInstruction ProcessServerResponseHeaders(RequestObj requestObj)
    {
      PluginInstruction pluginInstruction = new PluginInstruction();
    
      return pluginInstruction;
    }

    #endregion

  }
}