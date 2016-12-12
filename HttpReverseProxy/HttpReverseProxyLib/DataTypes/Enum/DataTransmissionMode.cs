namespace HttpReverseProxyLib.DataTypes
{
  public enum DataTransmissionMode : int
  {
    Undefined = 1,
    NoDataToTransfer = 2,
    Chunked = 3,
    ContentLength = 4,
    RelayBlindly = 5,
    ReadOneLine = 6,
    Error = 7
  }
}
