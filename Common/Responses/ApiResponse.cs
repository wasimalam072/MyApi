public class ApiResponse<T>
{
    [JsonPropertyName("statusCode")]
    public int StatusCode { get; init; }

    [JsonPropertyName("success")]
    public bool Success =>
        StatusCode is >= 200 and <= 299;

    [JsonPropertyName("message")]
    public string Message { get; init; }
        = string.Empty;

    [JsonPropertyName("errorCode")]
    [JsonIgnore(
        Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ErrorCode { get; init; }

    [JsonPropertyName("data")]
    [JsonIgnore(
        Condition = JsonIgnoreCondition.WhenWritingNull)]
    public T? Data { get; init; }

    [JsonPropertyName("errors")]
    [JsonIgnore(
        Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Errors { get; init; }

    [JsonPropertyName("traceId")]
    [JsonIgnore(
        Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TraceId { get; init; }

    [JsonPropertyName("timestampUtc")]
    public DateTimeOffset TimestampUtc { get; init; }
        = DateTimeOffset.UtcNow;

    /// <summary>
    /// Creates a successful API response.
    /// </summary>
    public static ApiResponse<T> CreateSuccess(
        int statusCode,
        string message,
        T? data,
        string? traceId = null)
    {
        return new ApiResponse<T>
        {
            StatusCode = statusCode,
            Message = message,
            Data = data,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates an unsuccessful API response.
    /// </summary>
    public static ApiResponse<T> CreateFailure(
        int statusCode,
        string message,
        string errorCode,
        string? traceId = null,
        IReadOnlyList<string>? errors = null)
    {
        return new ApiResponse<T>
        {
            StatusCode = statusCode,
            Message = message,
            ErrorCode = errorCode,
            Errors = errors,
            TraceId = traceId
        };
    }
}