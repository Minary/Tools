using System;
using System.Globalization;


namespace HttpReverseProxy.ToClient.Header
{

  public class Redirect
  {

    #region MEMBERS

    private static string statusLine = "HTTP/1.1 302 Found";
    private static string server = "Server: Apache";
    private static string date = string.Empty;
    private static string contentLength = "Content-Length: 0";
    private static string location = string.Empty;
    private static string connection = "Connection: close";

    #endregion


    #region PUBLIC

    public static string GetHeader(string locationParam, string serverNewLine)
    {
      location = string.Format("Location: {0}", locationParam);
      date = string.Format("Date: {0}", DateTime.Now.ToString("ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture));
      string header = string.Join(
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
