<?php

/*
 * This file is part of the project package.
 *
 * (c) Oleg Timchenko <evo9.81@gmail.com>
 */

namespace Yllta\DefaultBundle\EventListener;

use Doctrine\ORM\EntityManager;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Workflow\StateMachine;
use Yllta\DefaultBundle\Entity\Photo;
use Yllta\DefaultBundle\Event\PhotoStatusModerationEvent;
use Yllta\DefaultBundle\Event\PhotoModerationEvent;
use Yllta\DefaultBundle\Helper\YlltaEvents;

class PhotoStatusModeration
{
    /**
     * @var EntityManager
     */
    private $entityManager;

    /**
     * @var EventDispatcherInterface
     */
    private $dispatcher;

    /**
     * @var StateMachine
     */
    private $stateMachine;

    /**
     * PhotoStatusModeration constructor.
     * @param EntityManager            $entityManager
     * @param EventDispatcherInterface $dispatcher
     * @param StateMachine             $stateMachine
     */
    public function __construct(EntityManager $entityManager, EventDispatcherInterface $dispatcher, StateMachine $stateMachine)
    {
        $this->entityManager = $entityManager;
        $this->dispatcher = $dispatcher;
        $this->stateMachine = $stateMachine;
    }

    /**
     * @param PhotoStatusModerationEvent $event
     */
    public function onChangeStatusEvent(PhotoStatusModerationEvent $event)
    {
        $photo = $event->getPhoto();
        $moderator = $event->getModerator();
        $smTransition = $event->getSmTransition();
        $isApproved = $event->isApproved();

        if ($this->stateMachine->can($photo, $smTransition)) {
            $this->stateMachine->apply($photo, $smTransition);

            $photo->setModerator($moderator);
            $photo->setModeratedAt(new \DateTime('now'));

            $this->entityManager->flush();

            $event = new PhotoModerationEvent($photo, $isApproved);
            $this->dispatcher->dispatch(YlltaEvents::PHOTO_MODERATION, $event);
        }
    }
}