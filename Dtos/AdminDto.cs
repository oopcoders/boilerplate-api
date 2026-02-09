using System;

namespace boilerplate.Api.Dtos;

public class AdminDto
{
    public record AddRoleRequest(string UserEmail, string Role);
    public record RemoveRoleRequest(string UserEmail, string Role);
}
