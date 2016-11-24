namespace HttpReverseProxy.Plugin.Inject
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.Exceptions;

  public partial class Inject
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public PluginInstruction OnPostServerHeadersResponse(RequestObj requestObj)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      PluginInstruction instruction = new PluginInstruction();
      instruction.Instruction = Instruction.DoNothing;


      return instruction;
    }
  }
}
