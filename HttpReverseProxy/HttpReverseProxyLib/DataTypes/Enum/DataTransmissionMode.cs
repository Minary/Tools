namespace HttpReverseProxyLib.DataTypes.Enum
{
  public enum DataTransmissionMode : int
  {
    Undefined = 1,
    NoDataToTransfer = 2,
    Chunked = 3,
    FixedContentLength = 4,
    RelayBlindly = 5,
    ReadOneLine = 6,
    Error = 7
  }
}
