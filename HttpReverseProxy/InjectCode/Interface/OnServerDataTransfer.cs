namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxy.Plugin.InjectCode.DataTypes;
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
        throw new ProxyWarningException("The data chunk object is invalid");
      }

      if (Plugin.InjectCode.Config.InjectCodeRecords.Count <= 0)
      {
        return;
      }
     
      foreach (InjectCodeConfigRecord injectRecord in Plugin.InjectCode.Config.InjectCodeRecords)
      {
        if (injectRecord.HostnameRegex.Match(requestObj.ClientRequestObj.Host).Success == true  &&
            injectRecord.PathRegex.Match(requestObj.ClientRequestObj.RequestLine.Path).Success == true)
        {
          // 2. Decode bytes to UTF8
          string readableData = Encoding.UTF8.GetString(dataChunk.ContentData, 0, dataChunk.ContentDataLength);
          MatchCollection matches = Regex.Matches(readableData, injectRecord.TagRegex);
          if (matches.Count > 0)
          {
            string foundTag = matches[0].Groups[1].Value;
            string foundTagEscaped = Regex.Escape(foundTag);
            string replacementData = injectRecord.InjectionCodeFileContent;

            if (injectRecord.Position == TagPosition.before)
            {
              replacementData += replacementData + foundTag;
            }
            else
            {
              replacementData = foundTag + replacementData;
            }

            readableData = Regex.Replace(readableData, foundTagEscaped, replacementData);
            Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnServerDataTransfer(): Injected code from file {0} {1} the tag {2}. hostPattern={3}, pathPattern={4}",
              Path.GetFileName(injectRecord.InjectionCodeFile), injectRecord.Position, injectRecord.Tag, injectRecord.HostnameStr, injectRecord.PathStr);

            // Write data back to datapacket
            dataChunk.ContentData = Encoding.UTF8.GetBytes(readableData);
            dataChunk.ContentDataLength = dataChunk.ContentData.Length;

            break;
          }
        }
      }

      Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "InjectCode.OnServerDataTransfer(): ");
    }
  }
}