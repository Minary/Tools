using System;
using System.Globalization;


namespace HttpReverseProxy.ToClient.Header
{

  public class Redirect
  {

    #region MEMBERS

    private static string statusLine = string.Empty;
    private static string server = "Server: Apache";
    private static string date = string.Empty;
    private static string contentLength = "Content-Length: 0";
    private static string location = string.Empty;
    private static string connection = "Connection: close";

    #endregion


    #region PUBLIC

    public static string GetHeader(string statusCode, string statusDescription, string locationParam, string serverNewLine)
    {
      statusLine = $"HTTP/1.1 {statusCode} {statusDescription}";
      location = $"Location: {locationParam}";
      var tmpDate = DateTime.Now.ToString("ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture);
      date = $"Date: {tmpDate}";
      var header = string.Join(
                               serverNewLine,
                               statusLine,
                               server,
                               date,
                               contentLength,
                               location,
                               connection,
                               serverNewLine);

      return header;
    }

    #endregion

  }
}
