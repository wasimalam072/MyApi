namespace MyApi.Message;

public class CustomApiVersioningError : DefaultErrorResponseProvider
{
    public override IActionResult CreateResponse(ErrorResponseContext context)
    {
        // Customize the response message
        if (context.ErrorCode == "UnsupportedApiVersion")
        {
            var response = new ApiResponse<object>
            {
                StatusCode = StatusCodes.Status400BadRequest,
                Message = "The requested API version is not supported.",
                Data = null
            };

            return new ObjectResult(response)
            {
                StatusCode = StatusCodes.Status400BadRequest
            };
        }
        return base.CreateResponse(context);
    }
}