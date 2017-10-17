<?php

/*
 * This file is part of the project package.
 *
 * (c) Oleg Timchenko <evo9.81@gmail.com>
 */

namespace Yllta\DefaultBundle\Controller;

use FOS\UserBundle\Controller\SecurityController as BaseController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Yllta\DefaultBundle\Form\UserRegistrationType;
use Yllta\DefaultBundle\Form\UserNewPasswordType;
use Yllta\DefaultBundle\Form\UserPasswordRestoreType;
use Yllta\DefaultBundle\Entity\Page;
use Yllta\DefaultBundle\Helper\PageSlugs;
use FOS\UserBundle\FOSUserEvents;
use FOS\UserBundle\Event\FilterUserResponseEvent;
use Yllta\DefaultBundle\Event\PasswordRestoreEvent;
use Yllta\DefaultBundle\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Yllta\DefaultBundle\Helper\YlltaEvents;
use Yllta\DefaultBundle\Mixin\RepositoryTrait;

/**
 * Class SecurityController
 */
class SecurityController extends BaseController
{
    use RepositoryTrait;

    /**
     * @param Request $request
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function registrationAction(Request $request)
    {
        $page = $this->getPageRepository()->findOneBySlug(PageSlugs::REGISTRATION);

        $this->get('yllta_default.helper.content_helper')->setSeo($page);

        $userManager = $this->get('fos_user.user_manager');

        $user = $userManager->createUser();

        $form = $this->createForm(UserRegistrationType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted()) {
            if (!$form->isValid()) {
                $errors = $form->getErrors(true);

                $this->addFlash('error', $this->get('yllta_default.helper.content_helper')->prepareFormErrors($errors));
            } else {
                $dispatcher = $this->get('event_dispatcher');

                $user->setIp($request->getClientIp());

                $userManager->updateUser($user);

                $url = $this->generateUrl('yllta_default_page_information', ['slug' => PageSlugs::REGISTRATION_SUCCESS]);
                $response = new RedirectResponse($url);

                $event = new FilterUserResponseEvent($user, $request, $response);
                $dispatcher->dispatch(FOSUserEvents::REGISTRATION_COMPLETED, $event);

                return $response;
            }
        }

        return $this->render('YlltaDefaultBundle:security:registration.html.twig', [
            'form' => $form->createView(),
            'page' => $page,
        ]);
    }

    /**
     * Активация пользователя по ссылке из письма
     *
     * @param string $token
     *
     * @return RedirectResponse
     */
    public function registrationConfirmAction($token)
    {
        $userManager = $this->get('fos_user.user_manager');

        $user = $userManager->findUserBy(['confirmationToken' => $token]);

        if (!$user instanceof User) {
            throw $this->createNotFoundException(
                $this->get('translator')->trans('errors.user_not_found')
            );
        }

        $user->setEnabled(true);
        $user->setConfirmationToken(null);
        $userManager->updateUser($user);

        $token = new UsernamePasswordToken($user, null, 'main', $user->getRoles());
        $this->container->get('security.token_storage')->setToken($token);

        return $this->redirectToRoute(
            'yllta_default_security_new_password',
            ['id' => $user->getId()]
        );
    }

    /**
     * Создание нового пароля
     *
     * @param Request $request
     * @param User    $user
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function newPasswordAction(Request $request, User $user)
    {
        $page = $this->getPageRepository()->findOneBySlug(PageSlugs::NEW_PASSWORD);

        $this->get('yllta_default.helper.content_helper')->setSeo($page);

        $userManager = $this->get('fos_user.user_manager');

        $form = $this->createForm(UserNewPasswordType::class, $user);

        $form->handleRequest($request);

        if ($form->isSubmitted()) {
            if (!$form->isValid()) {
                $errors = $form->getErrors(true);

                $this->addFlash('error', $this->get('yllta_default.helper.content_helper')->prepareFormErrors($errors));
            } else {
                $userManager->updateUser($user);

                return $this->redirectToRoute('yllta_default_profile_index', ['id' => $user->getId()]);
            }

        }

        return $this->render('YlltaDefaultBundle:security:new-password.html.twig', [
            'page' => $page,
            'form' => $form->createView(),
        ]);
    }

    /**
     * Авторизация
     *
     * @param Request $request
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function loginAction(Request $request)
    {
        $page = $this->getPageRepository()->findOneBySlug(PageSlugs::LOGIN);

        $this->get('yllta_default.helper.content_helper')->setSeo($page);

        /** @var $session \Symfony\Component\HttpFoundation\Session\Session */
        $session = $request->getSession();

        $authErrorKey = Security::AUTHENTICATION_ERROR;
        $lastUsernameKey = Security::LAST_USERNAME;

        // get the error if any (works with forward and redirect -- see below)
        if ($request->attributes->has($authErrorKey)) {
            $error = $request->attributes->get($authErrorKey);
        } elseif (null !== $session && $session->has($authErrorKey)) {
            $error = $session->get($authErrorKey);
            $session->remove($authErrorKey);
        } else {
            $error = null;
        }

        if (!$error instanceof AuthenticationException) {
            $error = null; // The value does not come from the security component.
        } else {
            $errorMessage = $this->get('translator')->trans($error->getMessageKey(), $error->getMessageData(), 'security');
            $this->addFlash('error', $errorMessage);
        }

        // last username entered by the user
        $lastUsername = (null === $session) ? '' : $session->get($lastUsernameKey);

        $csrfToken = $this->has('security.csrf.token_manager')
            ? $this->get('security.csrf.token_manager')->getToken('authenticate')->getValue()
            : null;

        return $this->render('YlltaDefaultBundle:security:login.html.twig', [
            'page'          => $page,
            'last_username' => $lastUsername,
            'csrf_token'    => $csrfToken,
        ]);
    }

    /**
     * Промежуточная страница после успешной авторизации
     *
     * @return RedirectResponse
     */
    public function loginSuccessAction()
    {
        $authChecker = $this->get('security.authorization_checker');

        // Если администратор, перенаправляем в панель управления
        if ($authChecker->isGranted('ROLE_ADMIN')) {
            return $this->redirectToRoute('sonata_admin_dashboard');
        }

        // Если модератор, перенаправляем на страницу модерации
        if ($authChecker->isGranted('ROLE_MODERATOR')) {
            return $this->redirectToRoute('yllta_default_photo_moderation');
        }

        // Если обычный пользователь, перенаправляем в ЛК
        return $this->redirectToRoute('yllta_default_profile_index', [
            'id' => $this->getUser()->getId(),
        ]);
    }

    /**
     * Восстановление пароля
     *
     * @param Request $request
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function passwordRestoreAction(Request $request)
    {
        $page = $this->getPageRepository()->findOneBySlug(PageSlugs::PASSWORD_RESTORE);

        $this->get('yllta_default.helper.content_helper')->setSeo($page);

        $form = $this->createForm(UserPasswordRestoreType::class);

        $form->handleRequest($request);

        if ($form->isSubmitted()) {
            if (!$form->isValid()) {
                $errors = $form->getErrors(true);

                $this->addFlash('error', $this->get('yllta_default.helper.content_helper')->prepareFormErrors($errors));
            } else {
                $dispatcher = $this->get('event_dispatcher');

                $data = $form->getData();

                $event = new PasswordRestoreEvent($request, $data['email']);
                $dispatcher->dispatch(YlltaEvents::PASSWORD_RESTORE, $event);

                return $this->redirectToRoute('yllta_default_page_information', ['slug' => PageSlugs::PASSWORD_RESTORE_SUCCESS]);
            }
        }

        return $this->render('YlltaDefaultBundle:security:password-restore.html.twig', [
            'page' => $page,
            'form' => $form->createView(),
        ]);
    }

    /**
     * Изменение пароля по ссылке из письма
     *
     * @param string $token
     *
     * @return RedirectResponse
     */
    public function passwordRestoreCheckAction($token)
    {
        $userManager = $this->get('fos_user.user_manager');

        $user = $userManager->findUserBy(['confirmationToken' => $token]);

        if (!$user instanceof User) {
            throw $this->createNotFoundException(
                $this->get('translator')->trans('errors.user_not_found')
            );
        }

        $user->setConfirmationToken(null);
        $userManager->updateUser($user);

        $token = new UsernamePasswordToken($user, null, 'main', $user->getRoles());
        $this->container->get('security.token_storage')->setToken($token);

        return $this->redirectToRoute('yllta_default_security_new_password', ['id' => $user->getId()]);
    }
}