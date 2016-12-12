namespace HttpReverseProxyLib.DataTypes.Enum
{
  public enum RedirectType : int
  {
    Http2http2XX = 0,
    Http2Http3XX = 1,
    Http2Https3XXSameUrl = 2,
    Http2Https3XXDifferentUrl = 3,
    Error = 4
  }
}
