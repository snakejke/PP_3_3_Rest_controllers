package ru.kata.spring.boot_security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.doAnswer;
import static org.mockito.BDDMockito.times;
import static org.mockito.BDDMockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

@SpringBootTest
@AutoConfigureMockMvc
class AdminRestControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void createValidUserShouldSaveSuccessfully() throws Exception {

        User user = new User();
        user.setAge(33);
        user.setFirstName("test");
        user.setLastName("Test");
        user.setEmail("test@gmail.com");
        user.setPassword("123");

        doAnswer((Answer<Void>) invocation -> {
            User savedUser = invocation.getArgument(0);
            assertEquals("test", savedUser.getFirstName());
            assertEquals("Test", savedUser.getLastName());
            assertEquals("test@gmail.com", savedUser.getEmail());
            return null;
        }).when(userService).saveUser(any(User.class));

        ResultActions response = mockMvc.perform(post("/api/admin/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user)));

        response.andExpect(status().isCreated())
                .andDo(MockMvcResultHandlers.print())
                .andReturn();

        System.out.println("Тест прошел успешно! Пользователь создан.");

        verify(userService, times(1)).saveUser(any(User.class));
    }

}
