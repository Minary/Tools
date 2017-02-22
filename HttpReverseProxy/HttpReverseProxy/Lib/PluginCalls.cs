﻿namespace HttpReverseProxy.Lib
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Interface;
  using System;


  public class PluginCalls
  {

    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <returns></returns>
    public static PluginInstruction PostClientHeadersRequest(RequestObj requestObj)
    {
      PluginInstruction pluginInstr = new PluginInstruction();

      foreach (IPlugin tmpPlugin in Config.LoadedPlugins)
      {
        // If the plugin does not support the request type 
        // go to the next item.
        if ((tmpPlugin.Config.SupportedProtocols & requestObj.ProxyProtocol) != requestObj.ProxyProtocol)
        {
          continue;
        }

        try
        {
          pluginInstr = tmpPlugin.OnPostClientHeadersRequest(requestObj);

          if (pluginInstr.Instruction != Instruction.DoNothing)
          {
            return pluginInstr;
          }
        }
        catch (Exception ex)
        {
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Warnung, "PostClientHeadersRequest(EXCEPTION) : {0} -> {1}\r\n{2}", tmpPlugin.Config.Name, ex.Message, ex.StackTrace);
        }
      }

      pluginInstr = new PluginInstruction();
      pluginInstr.Instruction = Instruction.DoNothing;

      return pluginInstr;
    }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <returns></returns>
    public static PluginInstruction PostServerHeadersResponse(RequestObj requestObj)
    {
      PluginInstruction pluginInstr = new PluginInstruction();

      foreach (IPlugin tmpPlugin in Config.LoadedPlugins)
      {
        // If the plugin does not support the request type 
        // go to the next item.
        if ((tmpPlugin.Config.SupportedProtocols & requestObj.ProxyProtocol) != requestObj.ProxyProtocol)
        {
          continue;
        }

        try
        {
          pluginInstr = tmpPlugin.OnPostServerHeadersResponse(requestObj);

          if (pluginInstr.Instruction != Instruction.DoNothing)
          {
            return pluginInstr;
          }

          //// <-- Http2Https3XXDifferentUrl  --> do something
          //// <-- Http2Https3XXSameUrl       --> do something
        }
        catch (Exception ex)
        {
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Warnung, @"PostServerHeadersResponse(EXCEPTION) : {0} -> {1}\r\n{2}", tmpPlugin.Config.Name, ex.Message, ex.StackTrace);
        }
      }

      pluginInstr = new PluginInstruction();
      pluginInstr.Instruction = Instruction.DoNothing;

      return pluginInstr;
    }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="dataPacket"></param>
    public static void PostServerDataResponse(RequestObj requestObj, DataPacket dataPacket)
    {
      foreach (IPlugin tmpPlugin in Config.LoadedPlugins)
      {
        // If the plugin does not support the request type 
        // go to the next item.
        if ((tmpPlugin.Config.SupportedProtocols & requestObj.ProxyProtocol) != requestObj.ProxyProtocol)
        {
          continue;
        }

        try
        {
          tmpPlugin.OnPostServerDataResponse(requestObj, dataPacket);
        }
        catch (Exception ex)
        {
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Warnung, @"PostServerDataResponse(EXCEPTION) : {0} -> {1}\r\n{2}", tmpPlugin.Config.Name, ex.Message, ex.StackTrace);
        }
      }
    }

    #endregion


    #region PRIVATE

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginInstr"></param>
    /// <returns></returns>
    private static string PluginInstruction2string(Instruction pluginInstr)
    {
      string instructionStr = string.Empty;
      switch (pluginInstr)
      {
        case Instruction.DoNothing: instructionStr = "Do nothing";
          break;

        case Instruction.RedirectToNewUrl: instructionStr = "RedirectToNewUrl";
          break;

        case Instruction.SendBackStatus: instructionStr = "SendBackStatus";
          break;

        default: instructionStr = "InstructionError";
          break;
      }

      return instructionStr;
    }

    #endregion

  }
}
