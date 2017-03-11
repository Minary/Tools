namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.IO;
  using System.Text;
  using System.Text.RegularExpressions;


  public partial class InjectCode
  {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="dataChunk"></param>
    public void OnServerDataTransfer(RequestObj requestObj, DataChunk dataChunk)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (dataChunk == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords.ContainsKey(requestObj.ClientRequestObj.Host) == false)
      {
        return;
      }

      DataTypes.InjectCodeConfigRecord injectRecord = HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords[requestObj.ClientRequestObj.Host];
      if (Regex.Match(requestObj.ClientRequestObj.RequestLine.Path, injectRecord.Path, RegexOptions.IgnoreCase).Success == false)
      {
        return;
      }
      
      // 2. Decode bytes to UTF8
      string readableData = Encoding.UTF8.GetString(dataChunk.ContentData);
      MatchCollection matches = Regex.Matches(readableData, injectRecord.TagRegex);
      if (matches.Count > 0)
      {
        byte[] tmpDataBlock;
        string foundTag = matches[0].Groups[1].Value;
        string foundTagEscaped = Regex.Escape(foundTag);
        string replacementData = injectRecord.InjectionCodeFileContent;

        if (injectRecord.Position == DataTypes.TagPosition.before)
        {
          replacementData = replacementData + " " + foundTag;
        }
        else
        {
          replacementData = foundTag + " " + replacementData;
        }

        readableData = Regex.Replace(readableData, foundTagEscaped, replacementData);
        Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnServerDataTransfer(): Injected code from file {0} {1} the tag {2}", Path.GetFileName(injectRecord.InjectionCodeFile), injectRecord.Position, injectRecord.Tag);

        // Write data back to datapacket
        dataChunk.ContentData = tmpDataBlock = Encoding.UTF8.GetBytes(readableData);
        dataChunk.ContentDataLength = dataChunk.ContentData.Length;
      }

      Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "InjectCode.OnServerDataTransfer(): ");
    }
  }
}